"""
Fixtures for Paillier tests
"""

from collections.abc import Generator

import pytest

from tno.mpc.encryption_schemes.paillier import Paillier, PaillierCiphertext


@pytest.fixture(
    name="paillier_scheme_with_precision",
    scope="module",
)
def fixture_paillier_scheme_with_precision() -> Generator[Paillier, None, None]:
    """
    Constructs a Paillier scheme.

    :return: Initialized Paillier scheme with, or without, precision.
    """
    scheme = Paillier.from_security_parameter(
        key_length=64,
        precision=5,
    )
    yield scheme
    scheme.shut_down()


@pytest.fixture(
    name="paillier_scheme_without_precision",
    scope="module",
)
def fixture_paillier_scheme_without_precision() -> Generator[Paillier, None, None]:
    """
    Constructs a Paillier scheme.

    :return: Initialized Paillier scheme with, or without, precision.
    """
    scheme = Paillier.from_security_parameter(key_length=64)
    yield scheme
    scheme.shut_down()


@pytest.fixture(
    name="scheme",
    params=[True, False],
    ids=["with_precision", "without_precision"],
    scope="module",
)
def fixture_paillier_scheme(
    request: pytest.FixtureRequest,
    paillier_scheme_with_precision: Paillier,
    paillier_scheme_without_precision: Paillier,
) -> Paillier:
    """
    Constructs a Paillier scheme.

    :param request: Pytest request fixture.
    :param paillier_scheme_with_precision: Paillier fixture with precision.
    :param paillier_scheme_without_precision: Paillier fixture without precision.
    :return: Initialized Paillier scheme with, or without, precision.
    """
    if request.param:
        return paillier_scheme_with_precision
    return paillier_scheme_without_precision


@pytest.fixture(name="ciphertext", scope="class")
def fixture_ciphertext() -> Generator[PaillierCiphertext]:
    """
    Fixture for the ciphertext under test.

    :return: Ciphertext under test.
    """
    paillier = Paillier.from_security_parameter(
        key_length=64,
    )
    yield paillier.unsafe_encrypt(0)
    paillier.shut_down()
