"""
Fixtures for Paillier tests
"""

from typing import Generator

import pytest

from tno.mpc.encryption_schemes.paillier import Paillier


@pytest.fixture(
    name="paillier_scheme_with_precision",
    scope="module",
)
def fixture_paillier_scheme_with_precision() -> Generator[Paillier, None, None]:
    """
    Constructs a Paillier scheme

    :return: Initialized Paillier scheme with, or without, precision
    """
    scheme = Paillier.from_security_parameter(
        key_length=1024,
        precision=10,
        debug=False,
    )
    yield scheme
    scheme.shut_down()


@pytest.fixture(
    name="paillier_scheme_without_precision",
    scope="module",
)
def fixture_paillier_scheme_without_precision() -> Generator[Paillier, None, None]:
    """
    Constructs a Paillier scheme

    :return: Initialized Paillier scheme with, or without, precision
    """
    scheme = Paillier.from_security_parameter(key_length=1024, debug=False)
    yield scheme
    scheme.shut_down()


@pytest.fixture(
    name="paillier_scheme",
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
    Constructs a Paillier scheme

    :param request: pytest parameter specifying whether to use precision in scheme
    :param paillier_scheme_with_precision: Paillier fixture with precision
    :param paillier_scheme_without_precision: Paillier fixture without precision
    :return: Initialized Paillier scheme with, or without, precision
    """
    if request.param:
        return paillier_scheme_with_precision
    return paillier_scheme_without_precision
