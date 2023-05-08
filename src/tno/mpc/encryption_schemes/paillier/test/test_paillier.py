"""
This module tests the construction and use of Paillier instances.
"""
import itertools
from typing import Optional, Union

import pytest
from _pytest.fixtures import FixtureRequest

from tno.mpc.encryption_schemes.utils import USE_GMPY2, mod_inv, pow_mod
from tno.mpc.encryption_schemes.utils.fixed_point import FixedPoint

from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext
from tno.mpc.encryption_schemes.paillier.paillier import (
    WARN_INEFFICIENT_HOM_OPERATION,
    Plaintext,
    fxp,
)
from tno.mpc.encryption_schemes.paillier.test import (  # pylint: disable=unused-import
    conditional_pywarn,
    encrypt_with_freshness,
    fixture_paillier_scheme,
    fixture_paillier_scheme_with_precision,
    fixture_paillier_scheme_without_precision,
)

if USE_GMPY2:
    import gmpy2

test_values_integers = list(range(-5, 5))
test_values_floats = [float(_) / 40 for _ in range(-5, 5)]
test_values_integer_pairs = [(i, i + 1) for i in range(-5, 5)] + [
    (-i, i + 1) for i in range(5)
]
test_values_float_pairs = [
    (round(i * 10**-3, 3), round((i + 1) * 10**-2, 2)) for i in range(-5, 5)
] + [(round(-i * 10**-3, 3), round((i + 1) * 10**-2, 2)) for i in range(5)]
test_values_float_int_pairs = [
    (round(i * 10**-3, 3), i + 1) for i in range(-5, 5)
] + [(round(-i * 10**-3, 3), i + 1) for i in range(5)]
test_sampling_bounds = (
    [(_ - 0.1, _ + 1.5) for _ in range(0, 1000, 37)]
    + [(_, _ + 1) for _ in range(0, 1000, 37)]
    + [(-_, _ + 1) for _ in range(0, 1000, 37)]
    + [(-_ - 0.1, _ + 1.5) for _ in range(0, 1000, 37)]
)

if USE_GMPY2:
    test_values_integers.extend([gmpy2.mpz(_) for _ in test_values_integers])
    test_values_integer_pairs.extend(
        [(gmpy2.mpz(i1), gmpy2.mpz(i2)) for i1, i2 in test_values_integer_pairs]
    )
    test_values_float_int_pairs.extend(
        [(_, gmpy2.mpz(int_val)) for _, int_val in test_values_float_int_pairs]
    )


def test_setup(paillier_scheme: Paillier) -> None:
    """
    Test the correctness of the Paillier initializer.

    :param paillier_scheme: a Paillier instance
    """
    mu = paillier_scheme.secret_key.mu
    g = paillier_scheme.public_key.g
    n = paillier_scheme.public_key.n
    n_squared = paillier_scheme.public_key.n_squared
    lambda_ = paillier_scheme.secret_key.lambda_

    mu_prime = mod_inv(paillier_scheme.func_l(pow_mod(g, lambda_, n_squared), n), n)

    assert mu == mu_prime


@pytest.mark.parametrize(
    "scheme_fixture",
    ("paillier_scheme_with_precision", "paillier_scheme_without_precision"),
)
def test_min_max_values(scheme_fixture: str, request: FixtureRequest) -> None:
    """
    Verify that min_value and max_value span the feasible, symmetric domain.

    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    cardinality = (scheme.max_value - scheme.min_value) * 10**scheme.precision + 1

    assert scheme.min_value == -scheme.max_value
    assert cardinality == scheme.public_key.n


def test_scheme_comparison_true(paillier_scheme: Paillier) -> None:
    """
    Test equality of different Paillier schemes.

    :param paillier_scheme: a Paillier instance
    """
    public_key = paillier_scheme.public_key
    secret_key = paillier_scheme.secret_key
    precision = paillier_scheme.precision

    similar_scheme_with_secret_key = Paillier(
        public_key, secret_key, precision=precision
    )
    similar_scheme_with_secret_key.shut_down()
    similar_scheme_without_secret_key = Paillier(
        public_key, secret_key=None, precision=precision
    )
    similar_scheme_without_secret_key.shut_down()

    assert paillier_scheme == similar_scheme_with_secret_key
    assert paillier_scheme == similar_scheme_without_secret_key


def test_scheme_comparison_false(paillier_scheme: Paillier) -> None:
    """
    Test inequality of different Paillier schemes.

    :param paillier_scheme: a Paillier instance
    """
    public_key = paillier_scheme.public_key
    key_length = public_key.n.bit_length()
    secret_key = paillier_scheme.secret_key
    precision = paillier_scheme.precision

    scheme_different_pub_key = Paillier.from_security_parameter(
        key_length=key_length // 2, precision=precision
    )
    scheme_different_pub_key.shut_down()
    scheme_different_precision = Paillier(
        public_key, secret_key=secret_key, precision=precision + 1
    )
    scheme_different_precision.shut_down()

    assert paillier_scheme != scheme_different_pub_key
    assert paillier_scheme != scheme_different_precision


@pytest.mark.parametrize(
    "value, scheme_fixture",
    [(_, "paillier_scheme_with_precision") for _ in test_values_floats]
    + [(_, "paillier_scheme_with_precision") for _ in test_values_integers]
    + [(_, "paillier_scheme_without_precision") for _ in test_values_integers],
)
def test_safe_encryption(
    value: Union[float, int], scheme_fixture: str, request: FixtureRequest
) -> None:
    """
    Test encryption/decryption in the Paillier scheme.

    :param value: plaintext
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    fxp_value = FixedPoint.fxp(value)

    encrypted_value = scheme.encrypt(value)
    decrypted_value = scheme.decrypt(encrypted_value)

    assert encrypted_value.fresh is True
    assert fxp_value == decrypted_value


@pytest.mark.parametrize(
    "value, scheme_fixture",
    [(_, "paillier_scheme_with_precision") for _ in test_values_floats]
    + [(_, "paillier_scheme_with_precision") for _ in test_values_integers]
    + [(_, "paillier_scheme_without_precision") for _ in test_values_integers],
)
def test_unsafe_encryption(
    value: Union[float, int], scheme_fixture: str, request: FixtureRequest
) -> None:
    """
    Test unsafe encryption in the Paillier scheme.

    :param value: plaintext
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    fxp_value = FixedPoint.fxp(value)

    encrypted_value = scheme.unsafe_encrypt(value)
    decrypted_value = scheme.decrypt(encrypted_value)

    assert encrypted_value.fresh is False
    assert fxp_value == decrypted_value


@pytest.mark.parametrize(
    "value, scheme_fixture",
    [(_, "paillier_scheme_with_precision") for _ in test_values_floats]
    + [(_, "paillier_scheme_with_precision") for _ in test_values_integers]
    + [(_, "paillier_scheme_without_precision") for _ in test_values_integers],
)
@pytest.mark.parametrize("fresh", (True, False))
def test_copy_ciphertext(
    value: Union[float, int],
    fresh: bool,
    scheme_fixture: str,
    request: FixtureRequest,
) -> None:
    """
    Test correct copy of a ciphertext.

    :param value: plaintext
    :param fresh: freshness of the ciphertext
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    encrypted_value = encrypt_with_freshness(value, scheme, fresh)

    encrypted_value_prime = encrypted_value.copy()

    assert encrypted_value.fresh is fresh
    assert encrypted_value_prime.fresh is False
    assert encrypted_value == encrypted_value_prime
    assert encrypted_value is not encrypted_value_prime


@pytest.mark.parametrize(
    "value, scheme_fixture",
    [(_, "paillier_scheme_with_precision") for _ in test_values_floats]
    + [(_, "paillier_scheme_with_precision") for _ in test_values_integers]
    + [(_, "paillier_scheme_without_precision") for _ in test_values_integers],
)
def test_encryption_with_rerandomization(
    value: Union[float, int], scheme_fixture: str, request: FixtureRequest
) -> None:
    """
    Test encryption/decryption in the Paillier scheme with rerandomization of the ciphertext.

    :param value: plaintext
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    fxp_value = FixedPoint.fxp(value)
    encrypted_value: PaillierCiphertext = scheme.unsafe_encrypt(fxp_value)
    encrypted_value_fresh = encrypted_value.fresh

    encrypted_value_prime = encrypted_value.copy()
    encrypted_value_prime.randomize()
    decrypted_value_prime = scheme.decrypt(encrypted_value_prime)

    assert encrypted_value_fresh is False
    assert encrypted_value_prime.fresh is True
    assert encrypted_value != encrypted_value_prime
    assert fxp_value == decrypted_value_prime


@pytest.mark.parametrize(
    "value_1, value_2, scheme_fixture",
    [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_pairs]
    + [_ + ("paillier_scheme_with_precision",) for _ in test_values_integer_pairs]
    + [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_int_pairs]
    + [_ + ("paillier_scheme_without_precision",) for _ in test_values_integer_pairs],
)
@pytest.mark.parametrize(
    "fresh_1, fresh_2",
    itertools.product((True, False), (True, False)),
)
def test_homomorphic_addition(
    value_1: Union[float, int],
    value_2: Union[float, int],
    fresh_1: bool,
    fresh_2: bool,
    scheme_fixture: str,
    request: FixtureRequest,
) -> None:
    """
    Test homomorphic addition of two encrypted values.

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param fresh_1: freshness of first ciphertext
    :param fresh_2: freshness of second ciphertext
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    fxp_1 = FixedPoint.fxp(value_1, scheme.precision)
    fxp_2 = FixedPoint.fxp(value_2, scheme.precision)
    correct_sum = fxp_1 + fxp_2
    encrypted_value_1 = encrypt_with_freshness(value_1, scheme, fresh_1)
    encrypted_value_2 = encrypt_with_freshness(value_2, scheme, fresh_2)
    encrypted_value_2a = encrypt_with_freshness(value_2, scheme, fresh_2)

    with conditional_pywarn(fresh_1 or fresh_2, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_sum_both_enc = encrypted_value_1 + encrypted_value_2
    with conditional_pywarn(fresh_2, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_sum_plain1 = value_1 + encrypted_value_2a
    decrypted_sum_both_enc = scheme.decrypt(encrypted_sum_both_enc)
    decrypted_sum_plain1 = scheme.decrypt(encrypted_sum_plain1)

    assert decrypted_sum_both_enc == decrypted_sum_plain1 == correct_sum
    assert encrypted_value_1.fresh is False
    assert encrypted_value_2.fresh is False
    assert encrypted_value_2a.fresh is False
    assert encrypted_sum_both_enc.fresh is (fresh_1 or fresh_2)
    assert encrypted_sum_plain1.fresh is fresh_2


@pytest.mark.parametrize(
    "value_1, value_2, scheme_fixture",
    [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_pairs]
    + [_ + ("paillier_scheme_with_precision",) for _ in test_values_integer_pairs]
    + [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_int_pairs]
    + [_ + ("paillier_scheme_without_precision",) for _ in test_values_integer_pairs],
)
@pytest.mark.parametrize(
    "fresh_1, fresh_2",
    itertools.product((True, False), (True, False)),
)
def test_homomorphic_subtraction(
    value_1: Union[float, int],
    value_2: Union[float, int],
    fresh_1: bool,
    fresh_2: bool,
    scheme_fixture: str,
    request: FixtureRequest,
) -> None:
    """
    Test homomorphic subtraction of two encrypted values, both __sub__ and __rsub__.

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param fresh_1: freshness of first ciphertext
    :param fresh_2: freshness of second ciphertext
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    fxp_1 = FixedPoint.fxp(value_1, scheme.precision)
    fxp_2 = FixedPoint.fxp(value_2, scheme.precision)
    correct_diff = fxp_1 - fxp_2
    encrypted_value_1 = encrypt_with_freshness(value_1, scheme, fresh_1)
    encrypted_value_1a = encrypt_with_freshness(value_1, scheme, fresh_1)
    encrypted_value_2 = encrypt_with_freshness(value_2, scheme, fresh_2)
    encrypted_value_2a = encrypt_with_freshness(value_2, scheme, fresh_2)

    with conditional_pywarn(fresh_1 or fresh_2, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_diff_both_enc = encrypted_value_1 - encrypted_value_2
    with conditional_pywarn(fresh_2, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_diff_with_plain1 = value_1 - encrypted_value_2a
    with conditional_pywarn(fresh_1, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_diff_with_plain2 = encrypted_value_1a - value_2
    decrypted_diff_both_enc = scheme.decrypt(encrypted_diff_both_enc)
    decrypted_diff_with_plain1 = scheme.decrypt(encrypted_diff_with_plain1)
    decrypted_diff_with_plain2 = scheme.decrypt(encrypted_diff_with_plain2)

    assert decrypted_diff_both_enc == correct_diff
    assert decrypted_diff_with_plain1 == correct_diff
    assert decrypted_diff_with_plain2 == correct_diff
    assert encrypted_value_1.fresh is False
    assert encrypted_value_1a.fresh is False
    assert encrypted_value_2.fresh is False
    assert encrypted_value_2a.fresh is False
    assert encrypted_diff_both_enc.fresh is (fresh_1 or fresh_2)
    assert encrypted_diff_with_plain1.fresh is fresh_2
    assert encrypted_diff_with_plain2.fresh is fresh_1


@pytest.mark.parametrize(
    "value_1, value_2, scheme_fixture",
    [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_pairs]
    + [_ + ("paillier_scheme_with_precision",) for _ in test_values_integer_pairs]
    + [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_int_pairs]
    + [_ + ("paillier_scheme_without_precision",) for _ in test_values_integer_pairs],
)
def test_homomorphic_multiplication_ciphertexts_type_error(
    value_1: Union[float, int],
    value_2: Union[float, int],
    scheme_fixture: str,
    request: FixtureRequest,
) -> None:
    """
    Test homomorphic multiplication of two encrypted values. (The scheme should throw an error)

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    encrypted_value_1 = scheme.encrypt(value_1)
    encrypted_value_2 = scheme.encrypt(value_2)

    with pytest.raises(TypeError):
        encrypted_value_1 * encrypted_value_2


@pytest.mark.parametrize(
    "value_1, value_2, scheme_fixture",
    [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_pairs]
    + [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_int_pairs]
    + [_ + ("paillier_scheme_without_precision",) for _ in test_values_float_int_pairs],
)
def test_homomorphic_multiplication_float_scalar_type_error(
    value_1: int,
    value_2: Union[float, int],
    scheme_fixture: str,
    request: FixtureRequest,
) -> None:
    """
    Test the multiplication of an encrypted value with a plaintext float value.
    This should throw an error, as the scheme does not support float scalars.

    :param value_1: first plaintext value
    :param value_2: second plaintext value
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    encrypted_value_2 = scheme.encrypt(value_2)

    with pytest.raises(TypeError):
        encrypted_value_2 * value_1


@pytest.mark.parametrize(
    "value_1, value_2, scheme_fixture",
    [_ + ("paillier_scheme_with_precision",) for _ in test_values_float_int_pairs]
    + [_ + ("paillier_scheme_without_precision",) for _ in test_values_integer_pairs],
)
@pytest.mark.parametrize("fresh", (True, False))
def test_homomorphic_multiplication_int_scalar(
    value_1: Union[float, int],
    value_2: int,
    fresh: bool,
    scheme_fixture: str,
    request: FixtureRequest,
) -> None:
    """
    Test the multiplication of an encrypted integer value with a plaintext integer value.

    :param value_1: to be encrypted plaintext value
    :param value_2: scalar value
    :param fresh: freshness of the ciphertext
    :param scheme_fixture: name of a fixture for a Paillier instance
    :param request: pytest parameter specifying the fixture to use
    """
    scheme = request.getfixturevalue(scheme_fixture)
    fxp_1 = FixedPoint.fxp(value_1, scheme.precision)
    fxp_2 = FixedPoint.fxp(value_2, scheme.precision)
    correct_prod = fxp_1 * fxp_2
    encrypted_value_1 = encrypt_with_freshness(value_1, scheme, fresh)
    encrypted_value_1a = encrypt_with_freshness(value_1, scheme, fresh)

    with conditional_pywarn(fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_prod_1 = encrypted_value_1 * value_2
    with conditional_pywarn(fresh, WARN_INEFFICIENT_HOM_OPERATION):
        encrypted_prod_2 = value_2 * encrypted_value_1a
    decrypted_prod_1 = scheme.decrypt(encrypted_prod_1)
    decrypted_prod_2 = scheme.decrypt(encrypted_prod_2)

    assert correct_prod == decrypted_prod_1
    assert correct_prod == decrypted_prod_2
    assert encrypted_value_1.fresh is False
    assert encrypted_value_1a.fresh is False
    assert encrypted_prod_1.fresh is fresh
    assert encrypted_prod_2.fresh is fresh


@pytest.mark.parametrize(
    "lower_bound, upper_bound",
    [
        (1, -1),
        (0.111111111111111, 0.111111111111112),
        (-(2**3000), 0),
        (0, 2**3000),
    ],
)
def test_random_plaintext_invalid(
    paillier_scheme: Paillier,
    lower_bound: Optional[Plaintext],
    upper_bound: Optional[Plaintext],
) -> None:
    """
    Test if the random_plaintext functionality raises an exception for invalid intervals.

    :param paillier_scheme: a Paillier instance
    :param lower_bound: Integer lower bound (inclusive)
    :param upper_bound: Integer upper bound (exclusive)
    """
    with pytest.raises(ValueError):
        paillier_scheme.random_plaintext(lower_bound, upper_bound)


@pytest.mark.parametrize(
    "lower_bound, upper_bound", [(-10.111111111111111, -9), (99, 100.111111111111112)]
)
def test_random_plaintext_warning(
    paillier_scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
) -> None:
    """
    Test if the random_plaintext functionality raises a warning when input needs to be scaled down due to scheme
    precision.

    :param paillier_scheme: a Paillier instance
    :param lower_bound: Integer lower bound (inclusive)
    :param upper_bound: Integer upper bound (exclusive)
    """
    scaled_lower_bound = fxp(lower_bound, paillier_scheme.precision)
    scaled_upper_bound = fxp(upper_bound, paillier_scheme.precision)

    for _ in range(100):
        with pytest.warns(UserWarning):
            random_plaintext = paillier_scheme.random_plaintext(
                lower_bound, upper_bound
            )
        assert random_plaintext.precision == paillier_scheme.precision
        assert scaled_lower_bound <= random_plaintext < scaled_upper_bound


@pytest.mark.parametrize(
    "lower_bound, upper_bound",
    test_sampling_bounds + [(None, None), (10, None), (None, 10)],
)
def test_random_plaintext(
    paillier_scheme: Paillier,
    lower_bound: Optional[Plaintext],
    upper_bound: Optional[Plaintext],
) -> None:
    """
    Test if the random_plaintext functionality produces values in the given range, for valid inputs.

    :param paillier_scheme: a Paillier instance
    :param lower_bound: Integer lower bound (inclusive)
    :param upper_bound: Integer upper bound (exclusive)
    """
    if lower_bound is None:
        lower_bound = paillier_scheme.min_value
    else:
        lower_bound = fxp(lower_bound, paillier_scheme.precision)
    if upper_bound is None:
        upper_bound = paillier_scheme.max_value
    else:
        upper_bound = fxp(upper_bound, paillier_scheme.precision)

    for _ in range(100):
        random_plaintext = paillier_scheme.random_plaintext(lower_bound, upper_bound)
        assert random_plaintext.precision == paillier_scheme.precision
        assert lower_bound <= random_plaintext < upper_bound


@pytest.mark.parametrize(
    "lower_bound, upper_bound", [(-10.111111111111111, -9), (99, 100.111111111111112)]
)
@pytest.mark.parametrize("security_level", [1, 10, 40])
def test_sample_mask_warning(
    paillier_scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
    security_level: int,
) -> None:
    """
    Test if the sample_mask functionality raises a warning when input needs to be scaled down due to scheme
    precision.

    :param paillier_scheme: a Paillier instance
    :param lower_bound: Integer lower bound (inclusive)
    :param upper_bound: Integer upper bound (exclusive)
    :param security_level: required security level
    """
    scaled_lower_bound = fxp(lower_bound, paillier_scheme.precision)
    scaled_upper_bound = fxp(upper_bound, paillier_scheme.precision)
    interval_size = scaled_upper_bound - scaled_lower_bound

    for _ in range(100):
        with pytest.warns(UserWarning):
            random_mask = paillier_scheme.sample_mask(
                lower_bound, upper_bound, security_level
            )
        assert random_mask.precision == paillier_scheme.precision
        assert (
            -interval_size * 2 ** (security_level - 1)
            <= random_mask
            < interval_size * 2 ** (security_level - 1)
        )


@pytest.mark.parametrize("lower_bound, upper_bound", test_sampling_bounds)
@pytest.mark.parametrize("security_level", [None, 1, 10, 40])
def test_sample_mask(
    paillier_scheme: Paillier,
    lower_bound: Plaintext,
    upper_bound: Plaintext,
    security_level: Optional[int],
) -> None:
    """
    Test if the sample_mask functionality produces values in the right range

    :param paillier_scheme: a Paillier instance
    :param lower_bound: integer lower bound of domain where messages are pulled from
    :param upper_bound: integer upper bound of domain where messages are pulled from
    :param security_level: required security level
    """
    scaled_lower_bound = fxp(lower_bound, paillier_scheme.precision)
    scaled_upper_bound = fxp(upper_bound, paillier_scheme.precision)
    interval_size = scaled_upper_bound - scaled_lower_bound

    for _ in range(100):
        random_mask = paillier_scheme.sample_mask(
            scaled_lower_bound, scaled_upper_bound, security_level
        )
        assert random_mask.precision == paillier_scheme.precision
        if security_level is None:
            assert paillier_scheme.min_value <= random_mask <= paillier_scheme.max_value
        else:
            assert (
                -interval_size * 2 ** (security_level - 1)
                <= random_mask
                < interval_size * 2 ** (security_level - 1)
            )
