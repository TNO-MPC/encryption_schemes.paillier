"""
This module tests the construction and use of Paillier instances.
"""

from __future__ import annotations

import sys
from collections.abc import Generator
from typing import cast

import pytest
from _pytest.fixtures import FixtureRequest

from tno.mpc.encryption_schemes.templates.test import (
    BaseTestAdditiveHomomorphicCiphertext,
    BaseTestAdditiveHomomorphicEncryptionScheme,
    BaseTestHomomorphicCiphertext,
    BaseTestHomomorphicEncryptionScheme,
    BaseTestRandomizableCiphertext,
    BaseTestRandomizedHomomorphicEncryptionScheme,
)
from tno.mpc.encryption_schemes.utils import USE_GMPY2
from tno.mpc.encryption_schemes.utils.fixed_point import FixedPoint

from tno.mpc.encryption_schemes.paillier import (
    Paillier,
    PaillierCiphertext,
    PaillierPublicKey,
)
from tno.mpc.encryption_schemes.paillier.paillier import Plaintext, fxp

if sys.version_info < (3, 12):
    from typing_extensions import override
else:
    from typing import override

if USE_GMPY2:
    import gmpy2

TEST_SAMPLING_BOUNDS = [
    (-(30 + 1e-20), -(20 + 1e-20)),
    (-1, 1),
    (20 + 1e-20, 30 + 1e-20),
]
TEST_SAMPLING_BOUNDS_HIGH_PRECISION = [(-1, 1e-20), (1e-20, 1)]
TEST_SECURITY_LEVELS = [None, 1, 20]

TEST_VALUES_SINGLE = [-350, -1, 0, 1, 350, -234.56, -0.01, 0.01, 234.56]
if USE_GMPY2:
    TEST_VALUES_SINGLE.extend([gmpy2.mpz(x) for x in [-500, 500]])

# transform floats into ints, keep gmpy objects intact
TEST_VALUES_SINGLE_INTEGRAL = set(
    map(
        lambda v: int(v) if isinstance(v, float) else v,
        filter(lambda v: v >= 0, TEST_VALUES_SINGLE),
    )
)
TEST_VALUES_SINGLE_POS_INTEGRAL = set(
    filter(lambda v: v >= 0, TEST_VALUES_SINGLE_INTEGRAL)
)
TEST_VALUES_DUO = list(zip(TEST_VALUES_SINGLE, TEST_VALUES_SINGLE))


def test_min_max_values(scheme: Paillier) -> None:
    """
    Verify that min_value and max_value span the feasible, symmetric domain.

    :param scheme: Paillier scheme under test.
    """
    cardinality = (scheme.max_value - scheme.min_value) * 10**scheme.precision + 1

    assert scheme.min_value == -scheme.max_value
    assert cardinality == scheme.public_key.n


class TestPaillierCiphertext(
    BaseTestHomomorphicCiphertext,
    BaseTestAdditiveHomomorphicCiphertext,
    BaseTestRandomizableCiphertext,
):

    def test_given_ciphertext_when_copied_then_original_keeps_freshness(
        self,
        fixed_freshness_ciphertext: PaillierCiphertext,
    ) -> None:
        """
        Test to ensure that copying a ciphertext does not affect the original ciphertext's
        freshness.

        :param fixed_freshness_ciphertext: Ciphertext under test.
        """
        orig_freshness = fixed_freshness_ciphertext.fresh
        fixed_freshness_ciphertext.copy()
        assert orig_freshness == fixed_freshness_ciphertext.fresh

    def test_given_ciphertext_when_copied_then_copy_is_unfresh(
        self,
        fixed_freshness_ciphertext: PaillierCiphertext,
    ) -> None:
        """
        Test to ensure that a ciphertext's copy is unfresh.

        :param fixed_freshness_ciphertext: Ciphertext under test.
        """
        assert not fixed_freshness_ciphertext.copy().fresh

    def test_given_ciphertext_when_copied_then_copy_is_separate_and_identical(
        self,
        fixed_freshness_ciphertext: PaillierCiphertext,
    ) -> None:
        """
        Test to ensure that a ciphertext's copy is a separate, yet identical object.

        :param fixed_freshness_ciphertext: Ciphertext under test.
        """
        ct_copy = fixed_freshness_ciphertext.copy()
        assert fixed_freshness_ciphertext == ct_copy
        assert fixed_freshness_ciphertext is not ct_copy

    def test_multiplication_with_ciphertext_raises_typeerror(
        self,
        ciphertext: PaillierCiphertext,
    ) -> None:
        """
        Test that multiplication of two ciphertexts raises a TypeError.

        :param ciphertext: Ciphertext under test.
        """
        with pytest.raises(TypeError):
            _ = ciphertext * ciphertext

    def test_multiplication_with_float_raises_typeerror(
        self,
        ciphertext: PaillierCiphertext,
    ) -> None:
        """
        Test that multiplication of a ciphertext and a float raises a TypeError.

        :param ciphertext: Ciphertext under test.
        """
        with pytest.raises(TypeError):
            _ = 0.5 * ciphertext

    @pytest.mark.parametrize("scalar", [fxp(0), fxp(123), fxp(-1.23), fxp(0.123)])
    def test_multiplication_with_fixedpoint(
        self,
        ciphertext: PaillierCiphertext,
        scalar: FixedPoint,
    ) -> None:
        """
        Test that multiplication of a ciphertext with a FixedPoint has expected precision and value.

        :param ciphertext: Ciphertext under test.
        :param scalar: FixedPoint scalar to multiply ciphertext with.
        """
        result = ciphertext * scalar
        assert result.scheme.precision == ciphertext.scheme.precision + scalar.precision

        expected_value = scalar * ciphertext.scheme.decrypt(ciphertext)
        result_value = result.scheme.decrypt(result)
        assert expected_value == result_value


class TestPaillierScheme(
    BaseTestRandomizedHomomorphicEncryptionScheme,
    BaseTestHomomorphicEncryptionScheme,
    BaseTestAdditiveHomomorphicEncryptionScheme,
):
    @pytest.fixture(name="same_scheme", scope="class")
    def fixture_same_scheme(self, scheme: Paillier) -> Generator[Paillier]:
        """
        Fixture for the scheme under test.

        :param scheme: Different scheme that is considered equal.
        :return: Scheme under test.
        """
        pk = scheme.public_key
        prec = scheme.precision
        scheme = Paillier(public_key=pk, secret_key=None, precision=prec)
        yield scheme
        scheme.shut_down()

    @pytest.fixture(
        name="different_scheme", scope="class", params=["diff_pk", "diff_prec"]
    )
    def fixture_different_scheme(
        self, request: FixtureRequest, scheme: Paillier
    ) -> Paillier:
        """
        Fixture for the scheme under test.

        :param request: Pytest request fixture.
        :param scheme: Different scheme that is considered equal.
        :return: Scheme under test.
        """
        pk = scheme.public_key
        prec = scheme.precision
        if request.param == "diff_pk":
            pk = PaillierPublicKey(n=pk.n + 1, g=pk.g + 1)
        else:
            prec += 1
        return Paillier(public_key=pk, secret_key=None, precision=prec)

    @pytest.fixture(name="value", scope="class", params=TEST_VALUES_SINGLE)
    def fixture_value(self, request: FixtureRequest, scheme: Paillier) -> FixedPoint:
        """
        Fixture for returning plaintext values to use in all encryption scheme tests.

        :param request: Pytest request fixture.
        :param scheme: Paillier scheme under test.
        :return: Plaintext value.
        """
        return FixedPoint.initiate_from_float(
            cast(float, request.param), target_precision=scheme.precision
        )

    @override
    @pytest.fixture(
        name="value_transform_no_encoding",
        scope="class",
        params=TEST_VALUES_SINGLE_POS_INTEGRAL,
    )
    def fixture_value_transform_no_encoding(
        self, request: FixtureRequest
    ) -> int:  # pylint: disable=arguments-renamed
        """
        Plaintext value to use in transformation tests that skip encoding.

        :param request: Pytest request fixture.
        :return: Plaintext value.
        """
        return cast(int, request.param)

    @override
    @pytest.fixture(
        name="value_mul",
        scope="class",
        params=TEST_VALUES_SINGLE_INTEGRAL,
    )
    def fixture_value_mul(
        self, request: FixtureRequest
    ) -> int:  # pylint: disable=argument-renamed
        """
        Fixture for returning plaintext values to use in all multiplication test.

        :param request: Pytest request fixture.
        :return: Plaintext value.
        """
        return cast(int, request.param)

    @pytest.fixture(name="ciphertext", scope="class")
    def fixture_ciphertext(
        self, scheme: Paillier, value: FixedPoint
    ) -> PaillierCiphertext:
        """
        Fixture for returning ciphertexts to use in all encryption scheme tests.

        :param scheme: Scheme under test.
        :param value: Value to encrypt.
        :return: Ciphertext.
        """
        return scheme.encrypt(value)

    @pytest.fixture(
        name="ciphertext_pair",
        scope="class",
        params=TEST_VALUES_DUO,
        ids=str,
    )
    def fixture_ciphertext_pair(
        self, request: FixtureRequest, scheme: Paillier
    ) -> tuple[PaillierCiphertext, PaillierCiphertext]:
        """
        Fixture for returning ciphertext pairs to use in all encryption scheme tests.

        :param request: Pytest request fixture.
        :param scheme: Scheme under test.
        :return: Ciphertext pair.
        """
        v1, v2 = cast(tuple[FixedPoint, FixedPoint], request.param)
        return (scheme.encrypt(v1), scheme.encrypt(v2))


@pytest.mark.parametrize(
    "lower_bound, upper_bound",
    [
        (1, -1),
        (0.111111111111111, 0.111111111111112),
        (-(2**3000), 0),
        (0, 2**3000),
    ],
)
def test_requesting_random_plaintext_in_invalid_range_raises_valueerror(
    scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
) -> None:
    """
    Test that requesting a random plaintext in an invalid range raises a ValueError.

    :param scheme: Scheme under test.
    :param lower_bound: Integer lower bound (inclusive).
    :param upper_bound: Integer upper bound (exclusive).
    """
    with pytest.raises(ValueError):
        scheme.random_plaintext(lower_bound, upper_bound)


@pytest.mark.parametrize(
    "lower_bound, upper_bound", TEST_SAMPLING_BOUNDS_HIGH_PRECISION
)
def test_requesting_random_plaintext_in_high_precision_range_raises_userwarning(
    scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
) -> None:
    """
    Test that the random_plaintext functionality raises a warning when input needs to be scaled
    down due to scheme precision.

    :param scheme: Scheme under test.
    :param lower_bound: Integer lower bound (inclusive).
    :param upper_bound: Integer upper bound (exclusive).
    """
    with pytest.warns(UserWarning):
        scheme.random_plaintext(lower_bound, upper_bound)


@pytest.mark.parametrize("lower_bound, upper_bound", TEST_SAMPLING_BOUNDS)
def test_requesting_random_plaintext_in_any_precision_range_yields_plaintext_with_scheme_precision(
    scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
) -> None:
    """
    Test that the random_plaintext functionality correctly scales to scheme precision.

    :param scheme: Scheme under test.
    :param lower_bound: Integer lower bound (inclusive).
    :param upper_bound: Integer upper bound (exclusive).
    """
    pt = scheme.random_plaintext(lower_bound, upper_bound)

    assert scheme.precision == pt.precision


@pytest.mark.parametrize(
    "lower_bound, upper_bound", TEST_SAMPLING_BOUNDS_HIGH_PRECISION
)
@pytest.mark.parametrize("security_level", TEST_SECURITY_LEVELS)
def test_requesting_mask_in_high_precision_range_raises_userwarning(
    scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
    security_level: int | None,
) -> None:
    """
    Test that the mask functionality raises a warning when input needs to be scaled
    down due to scheme precision.

    :param scheme: Scheme under test.
    :param lower_bound: Integer lower bound (inclusive).
    :param upper_bound: Integer upper bound (exclusive).
    :param security_level: Required security level.
    """
    with pytest.warns(UserWarning):
        scheme.sample_mask(lower_bound, upper_bound, security_level=security_level)


@pytest.mark.parametrize("lower_bound, upper_bound", TEST_SAMPLING_BOUNDS)
@pytest.mark.parametrize("security_level", TEST_SECURITY_LEVELS)
def test_sample_mask_produces_valid_outputs(
    scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
    security_level: int | None,
) -> None:
    """
    Test if the sample_mask functionality produces values in the right range.

    :param scheme: Scheme under test.
    :param lower_bound: Integer lower bound of domain where messages are pulled from.
    :param upper_bound: Integer upper bound of domain where messages are pulled from.
    :param security_level: Required security level.
    """
    scaled_lower_bound = fxp(lower_bound, scheme.precision)
    scaled_upper_bound = fxp(upper_bound, scheme.precision)
    interval_size = scaled_upper_bound - scaled_lower_bound

    nr_iterations = 100
    masks = [
        scheme.sample_mask(
            scaled_lower_bound, scaled_upper_bound, security_level=security_level
        )
        for _ in range(nr_iterations)
    ]

    assert all(scheme.precision == m.precision for m in masks)
    if security_level is None:
        assert all(scheme.min_value <= m <= scheme.max_value for m in masks)
    else:
        assert all(
            -interval_size * 2 ** (security_level - 1)
            <= m
            < interval_size * 2 ** (security_level - 1)
            for m in masks
        )
