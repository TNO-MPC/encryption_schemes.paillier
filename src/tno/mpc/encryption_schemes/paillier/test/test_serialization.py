"""
This module tests the serialization of Paillier instances.
"""
import asyncio
import warnings
from typing import Any, Generator, Tuple

import pytest

from tno.mpc.communication import Pool
from tno.mpc.communication.test.pool_fixtures_http import (  # pylint: disable=unused-import
    event_loop,
    fixture_pool_http_2p,
    fixture_pool_http_3p,
)

from tno.mpc.encryption_schemes.paillier import (
    EncryptionSchemeWarning,
    Paillier,
    PaillierCiphertext,
    PaillierPublicKey,
    PaillierSecretKey,
)
from tno.mpc.encryption_schemes.paillier.paillier import WARN_UNFRESH_SERIALIZATION
from tno.mpc.encryption_schemes.paillier.test import encrypt_with_freshness


def paillier_scheme(with_precision: bool) -> Paillier:
    """
    Constructs a Paillier scheme

    :param with_precision: boolean specifying whether to use precision in scheme
    :return: Initialized Paillier scheme with, or without, precision
    """
    if with_precision:
        return Paillier.from_security_parameter(
            key_length=1024,
            precision=10,
            debug=False,
        )
    return Paillier.from_security_parameter(key_length=1024, debug=False)


def fibonacci_generator(elements: int) -> Generator[int, None, None]:
    """
    Generator for the fibonacci sequence.

    :param elements: number of elements that the generator should generate
    :return: elements of the fibonacci sequence
    """
    left = 0
    right = 1
    for _ in range(elements):
        yield left
        left, right = right, left + right


@pytest.mark.parametrize("with_precision", (True, False))
def test_serialization_public_key(with_precision: bool) -> None:
    """
    Test to determine whether the public key serialization works properly for schemes.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    public_key = scheme.public_key
    public_key_prime = PaillierPublicKey.deserialize(public_key.serialize())
    scheme.shut_down()
    assert public_key == public_key_prime


@pytest.mark.parametrize("with_precision", (True, False))
def test_serialization_secret_key(with_precision: bool) -> None:
    """
    Test to determine whether the secret key serialization works properly for schemes.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    secret_key = scheme.secret_key
    secret_key_prime = PaillierSecretKey.deserialize(secret_key.serialize())
    scheme.shut_down()
    assert secret_key == secret_key_prime


@pytest.mark.parametrize("with_precision", (True, False))
def test_serialization_paillier_no_share(with_precision: bool) -> None:
    """
    Test to determine whether the paillier scheme serialization works properly for schemes
    when the secret key SHOULD NOT be serialized.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    # by default the secret key is not serialized, but equality should then still hold
    scheme_prime = Paillier.deserialize(scheme.serialize())
    scheme.shut_down()
    scheme_prime.shut_down()
    # secret key is still shared due to local instance sharing
    assert scheme_prime.secret_key is scheme_prime.secret_key
    assert scheme == scheme_prime

    # this time empty the list of global instances after serialization
    scheme_serialized = scheme.serialize()
    Paillier.clear_instances()
    scheme_prime2 = Paillier.deserialize(scheme_serialized)
    scheme.shut_down()
    scheme_prime2.shut_down()
    assert scheme_prime2.secret_key is None
    assert scheme == scheme_prime2


@pytest.mark.parametrize("with_precision", (True, False))
def test_serialization_paillier_share(with_precision: bool) -> None:
    """
    Test to determine whether the paillier scheme serialization works properly for schemes
    when the secret key SHOULD be serialized.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme.share_secret_key = True
    # We indicated that the secret key should be serialized, so this should be equal
    scheme_prime = Paillier.deserialize(scheme.serialize())
    scheme_prime.shut_down()
    scheme.shut_down()
    assert scheme == scheme_prime


@pytest.mark.parametrize(
    "value, with_precision",
    [(_, True) for _ in fibonacci_generator(25)]
    + [(_, False) for _ in fibonacci_generator(25)]
    + [(_ / 1e6, True) for _ in fibonacci_generator(25)],
)
def test_serialization_randomization_unfresh(value: int, with_precision: bool) -> None:
    """
    Test to determine whether the paillier ciphertext serialization correctly randomizes non-fresh
    ciphertexts.

    :param value: value to serialize
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    ciphertext = scheme.unsafe_encrypt(value)
    val_pre_serialize = ciphertext.peek_value()

    with pytest.warns(EncryptionSchemeWarning, match=WARN_UNFRESH_SERIALIZATION):
        ciphertext.serialize()
    val_post_serialize = ciphertext.peek_value()
    scheme.shut_down()

    assert val_pre_serialize != val_post_serialize
    assert ciphertext.fresh is False


@pytest.mark.parametrize(
    "value, with_precision",
    [(_, True) for _ in fibonacci_generator(25)]
    + [(_, False) for _ in fibonacci_generator(25)]
    + [(_ / 1e6, True) for _ in fibonacci_generator(25)],
)
def test_serialization_randomization_fresh(value: int, with_precision: bool) -> None:
    """
    Test to determine whether the paillier ciphertext serialization correctly does not randomize
    fresh ciphertexts.

    :param value: value to serialize
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    ciphertext = scheme.encrypt(value)
    val_pre_serialize = ciphertext.peek_value()

    ciphertext.serialize()
    val_post_serialize = ciphertext.peek_value()
    scheme.shut_down()

    assert val_pre_serialize == val_post_serialize
    assert ciphertext.fresh is False


@pytest.mark.parametrize(
    "value, with_precision",
    [(_, True) for _ in fibonacci_generator(25)]
    + [(_, False) for _ in fibonacci_generator(25)]
    + [(_ / 1e6, True) for _ in fibonacci_generator(25)],
)
@pytest.mark.parametrize("fresh", (True, False))
def test_serialization_ciphertext(
    value: int, fresh: bool, with_precision: bool
) -> None:
    """
    Test to determine whether the paillier ciphertext serialization works properly.

    :param value: value to serialize
    :param fresh: freshness of ciphertext
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    ciphertext = encrypt_with_freshness(value, scheme, fresh)
    with warnings.catch_warnings():
        # The unfresh serialization warning is not in scope of this test.
        warnings.filterwarnings("ignore", WARN_UNFRESH_SERIALIZATION, UserWarning)
        ciphertext_prime = PaillierCiphertext.deserialize(ciphertext.serialize())
    scheme.shut_down()
    assert ciphertext == ciphertext_prime
    assert ciphertext.fresh is False
    assert ciphertext_prime.fresh is False


@pytest.mark.parametrize("with_precision", (True, False))
def test_unrelated_instances(with_precision: bool) -> None:
    """
    Test whether the from_id_arguments and id_from_arguments methods works as intended.
    The share_secret_key variable should not influence the identifier.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    public_key = scheme.public_key
    secret_key = scheme.secret_key

    paillier_1 = Paillier(
        public_key=public_key, secret_key=None, precision=0, share_secret_key=False
    )
    paillier_1_prime = Paillier(
        public_key=public_key, secret_key=secret_key, precision=0, share_secret_key=True
    )
    assert paillier_1.identifier == paillier_1_prime.identifier
    paillier_1.save_globally()
    paillier_2 = Paillier.from_id_arguments(public_key=public_key, precision=0)
    paillier_3 = Paillier(public_key=public_key, precision=10, secret_key=None)
    assert paillier_1.identifier != paillier_3.identifier
    with pytest.raises(KeyError):
        _paillier_4 = Paillier.from_id_arguments(public_key=public_key, precision=10)

    paillier_3.save_globally()
    paillier_4 = Paillier.from_id_arguments(public_key=public_key, precision=10)
    paillier_1.shut_down()
    paillier_1_prime.shut_down()
    paillier_2.shut_down()
    paillier_3.shut_down()
    paillier_4.shut_down()
    scheme.shut_down()

    assert paillier_1 is paillier_2
    assert paillier_1 == paillier_2
    assert paillier_1 is not paillier_3
    assert paillier_1 != paillier_3
    assert paillier_2 is not paillier_4
    assert paillier_2 != paillier_4
    assert paillier_3 is paillier_4
    assert paillier_3 == paillier_4


@pytest.mark.parametrize("with_precision", (True, False))
def test_related_serialization(with_precision: bool) -> None:
    """
    Test whether deserialization of ciphertexts results in correctly deserialized schemes. Because
    ciphertexts are connected to schemes, you want ciphertexts coming from the same scheme to
    still have the same scheme when they are deserialized.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    ciphertext_1 = scheme.encrypt(1)
    ciphertext_2 = scheme.encrypt(2)
    ser_1 = ciphertext_1.serialize()
    ser_2 = ciphertext_2.serialize()
    new_ciphertext_1 = PaillierCiphertext.deserialize(ser_1)
    new_ciphertext_2 = PaillierCiphertext.deserialize(ser_2)

    new_ciphertext_1.scheme.shut_down()
    scheme.shut_down()

    assert (
        new_ciphertext_1.scheme
        is new_ciphertext_2.scheme
        is ciphertext_1.scheme
        is ciphertext_2.scheme
    )


@pytest.mark.parametrize("with_precision", (True, False))
def test_instances_from_security_param(with_precision: bool) -> None:
    """
    Test whether the get_instance_from_sec_param method works as intended. If a paillier scheme
    with the given parameters has already been created before, then that exact same scheme should be
    returned. Otherwise, a new scheme should be generated with those parameters.

    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    new_paillier_1 = Paillier.from_security_parameter(256)
    new_paillier_1.save_globally()
    new_paillier_2: Paillier = Paillier.from_id(new_paillier_1.identifier)
    new_paillier_3 = Paillier.from_security_parameter(256)

    new_paillier_1.shut_down()
    new_paillier_2.shut_down()
    new_paillier_3.shut_down()
    scheme.shut_down()

    assert new_paillier_1 is new_paillier_2
    assert new_paillier_1 is not new_paillier_3
    assert new_paillier_2 is not new_paillier_3
    assert new_paillier_1 != new_paillier_3
    assert new_paillier_2 != new_paillier_3


async def send_and_receive(pools: Tuple[Pool, Pool], obj: Any) -> Any:
    """
    Method that sends objects from one party to another.

    :param pools: collection of communication pools
    :param obj: object to be sent
    :return: the received object
    """
    # send from host 1 to host 2
    await pools[0].send("local1", obj)
    item = await pools[1].recv("local0")
    return item


@pytest.mark.asyncio
@pytest.mark.parametrize("with_precision", (True, False))
async def test_sending_and_receiving(
    pool_http_2p: Tuple[Pool, Pool], with_precision: bool
) -> None:
    """
    This test ensures that serialisation logic is correctly loading into the communication module.

    :param pool_http_2p: collection of communication pools
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    scheme_prime = await send_and_receive(pool_http_2p, scheme)
    assert Paillier.from_id(scheme.identifier) is scheme
    assert scheme_prime is scheme
    # the scheme has been sent once, so the httpclients should be in the scheme's client
    # history.
    assert len(scheme.client_history) == 2
    assert scheme.client_history[0] == pool_http_2p[0].pool_handlers["local1"]
    assert scheme.client_history[1] == pool_http_2p[1].pool_handlers["local0"]

    encryption = scheme.encrypt(plaintext=42)
    encryption_prime = await send_and_receive(pool_http_2p, encryption)
    encryption_prime.scheme.shut_down()
    assert encryption == encryption_prime

    public_key_prime = await send_and_receive(pool_http_2p, scheme.public_key)
    assert scheme.public_key == public_key_prime

    secret_key_prime = await send_and_receive(pool_http_2p, scheme.secret_key)
    assert scheme.secret_key == secret_key_prime


@pytest.mark.asyncio
@pytest.mark.parametrize("with_precision", (True, False))
async def test_broadcasting(
    pool_http_3p: Tuple[Pool, Pool, Pool], with_precision: bool
) -> None:
    """
    This test ensures that broadcasting ciphertexts works as expected.

    :param pool_http_3p: collection of communication pools
    :param with_precision: boolean specifying whether to use precision in scheme
    """
    scheme = paillier_scheme(with_precision)
    await asyncio.gather(
        *(
            pool_http_3p[0].send("local1", scheme),
            pool_http_3p[0].send("local2", scheme),
        )
    )
    scheme_prime_1, scheme_prime_2 = await asyncio.gather(
        *(pool_http_3p[1].recv("local0"), pool_http_3p[2].recv("local0"))
    )
    assert Paillier.from_id(scheme.identifier) is scheme
    assert scheme_prime_1 is scheme
    assert scheme_prime_2 is scheme
    # the scheme has been sent once to each party, so the httpclients should be in the scheme's client
    # history.
    assert len(scheme.client_history) == 3
    assert pool_http_3p[0].pool_handlers["local1"] in scheme.client_history
    assert pool_http_3p[0].pool_handlers["local2"] in scheme.client_history
    assert pool_http_3p[1].pool_handlers["local0"] in scheme.client_history
    assert pool_http_3p[2].pool_handlers["local0"] in scheme.client_history

    encryption = scheme.encrypt(plaintext=42)
    await pool_http_3p[0].broadcast(encryption, "msg_id")
    encryption_prime_1, encryption_prime_2 = await asyncio.gather(
        *(
            pool_http_3p[1].recv("local0", "msg_id"),
            pool_http_3p[2].recv("local0", "msg_id"),
        )
    )

    encryption_prime_1.scheme.shut_down()

    assert encryption == encryption_prime_1
    assert encryption == encryption_prime_2
