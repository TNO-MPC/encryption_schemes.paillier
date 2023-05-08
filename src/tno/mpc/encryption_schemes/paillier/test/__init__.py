"""
Testing module of the tno.mpc.encryption_schemes.paillier library
"""

from contextlib import contextmanager
from typing import Generator, Iterator

import pytest
from _pytest.fixtures import FixtureRequest

from tno.mpc.encryption_schemes.paillier import (
    EncryptionSchemeWarning,
    Paillier,
    PaillierCiphertext,
)
from tno.mpc.encryption_schemes.paillier.paillier import Plaintext


def encrypt_with_freshness(
    m: Plaintext, scheme: Paillier, safe: bool
) -> PaillierCiphertext:
    """
    Encrypt a plaintext in safe or unsafe mode.

    Safe mode will yield a fresh ciphertext, unsafe mode will yield a non-fresh ciphertext.

    :param m: Plaintext message to be encrypted
    :param scheme: Scheme to encrypt the message with
    :param safe: Perform safe encrypt if true, unsafe encrypt otherwise
    :return: PaillierCiphertext object with requested freshness
    """
    if safe:
        return scheme.encrypt(m)
    return scheme.unsafe_encrypt(m)


@contextmanager
def conditional_pywarn(truthy: bool, match: str) -> Iterator[None]:
    """
    Conditionally wraps statement in pytest.warns context manager.

    :param truthy: Flags whether statement should be ran in pytest.warns
    :param match: Match parameter for pytest.warns
    :return: _description_
    :yield: _description_
    """
    if truthy:
        with pytest.warns(EncryptionSchemeWarning) as record:
            yield
            assert (
                len(record) >= 1  # Duplicate warnings possible
            ), f"Expected to catch one EncryptionSchemeWarning, caught {len(record)}."
            for rec_msg in (str(rec.message) for rec in record):
                assert (
                    rec_msg == match
                ), f'Expected message "{match}", received message "{rec_msg}".'
    else:
        yield


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
    request: FixtureRequest,
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
