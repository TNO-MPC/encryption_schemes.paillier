import asyncio
import pytest

from tno.mpc.encryption_schemes.paillier import (
    Paillier,
    PaillierCiphertext,
    PaillierPublicKey,
    PaillierSecretKey,
)

from tno.mpc.encryption_schemes.paillier.test.pool_fixtures_http import pool_http_2p

paillier_scheme: Paillier = Paillier.from_security_parameter(key_length=1024)
paillier_scheme_floats: Paillier = Paillier.from_security_parameter(
    key_length=1024, precision=10
)


def fib_generator(n):
    a = 0
    b = 1
    for _ in range(n):
        yield a
        a, b = b, a + b


def test_serialization_pubkey_int():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    pk = paillier_scheme.public_key
    pk_prime = PaillierPublicKey.deserialize(pk.serialize())
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert pk == pk_prime


def test_serialization_pubkey_float():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    pk = paillier_scheme_floats.public_key
    pk_prime = PaillierPublicKey.deserialize(pk.serialize())
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert pk == pk_prime


def test_serialization_seckey_int():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    sk = paillier_scheme.secret_key
    sk_prime = PaillierSecretKey.deserialize(sk.serialize())
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert sk == sk_prime


def test_serialization_seckey_float():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    sk = paillier_scheme_floats.secret_key
    sk_prime = PaillierSecretKey.deserialize(sk.serialize())
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert sk == sk_prime


def test_serialization_paillier_int_no_share():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    scheme = paillier_scheme
    # by default the secret key is not serialized, but equality should then still hold
    scheme_prime = Paillier.deserialize(scheme.serialize())
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    scheme_prime.shut_down()
    assert scheme == scheme_prime


def test_serialization_paillier_float_no_share():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    scheme = paillier_scheme_floats
    # by default the secret key is not serialized, but equality should then still hold
    scheme_prime = Paillier.deserialize(scheme.serialize())
    scheme_prime.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert scheme == scheme_prime


def test_serialization_paillier_int():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    scheme = paillier_scheme
    scheme.share_secret_key = True
    # We indicated that the secret key should be serialized, so this should be equal
    scheme_prime = Paillier.deserialize(scheme.serialize())
    scheme_prime.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert scheme == scheme_prime


def test_serialization_paillier_float():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    scheme = paillier_scheme_floats
    scheme.share_secret_key = True
    # We indicated that the secret key should be serialized, so this should be equal
    scheme_prime = Paillier.deserialize(scheme.serialize())
    scheme_prime.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert scheme == scheme_prime


@pytest.mark.parametrize("val", list(fib_generator(25)))
def test_serialization_ciphertext_int(val):
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    ciphertext = paillier_scheme.encrypt(val)
    ciphertext_prime = PaillierCiphertext.deserialize(ciphertext.serialize())
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert ciphertext == ciphertext_prime


@pytest.mark.parametrize("val", [i / 2 ** 25 for i in fib_generator(25)])
def test_serialization_ciphertext_float(val):
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    ciphertext = paillier_scheme.encrypt(val)
    ciphertext_prime = PaillierCiphertext.deserialize(ciphertext.serialize())
    ciphertext_prime.scheme.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()
    assert ciphertext == ciphertext_prime


def test_unrelated_instances():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    pk = paillier_scheme.public_key
    sk = paillier_scheme.secret_key

    paillier_1 = Paillier.get_instance(public_key=pk, secret_key=sk, precision=0)
    paillier_2 = Paillier.get_instance(public_key=pk, secret_key=sk, precision=0)
    paillier_3 = Paillier.get_instance(public_key=pk, secret_key=sk, precision=10)
    paillier_4 = Paillier.get_instance(public_key=pk, secret_key=sk, precision=10)

    paillier_1.shut_down()
    paillier_2.shut_down()
    paillier_3.shut_down()
    paillier_4.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()

    assert paillier_1 is paillier_2
    assert paillier_1 is not paillier_3
    assert paillier_2 is not paillier_4
    assert paillier_3 is paillier_4


def test_related_serialization():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    ciphertext_1 = paillier_scheme.encrypt(1)
    ciphertext_2 = paillier_scheme.encrypt(2)
    ser_1 = ciphertext_1.serialize()
    ser_2 = ciphertext_2.serialize()
    new_ciphertext_1 = PaillierCiphertext.deserialize(ser_1)
    new_ciphertext_2 = PaillierCiphertext.deserialize(ser_2)

    new_ciphertext_1.scheme.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()

    assert new_ciphertext_1.scheme is new_ciphertext_2.scheme
    assert ciphertext_1.scheme is ciphertext_2.scheme
    assert new_ciphertext_1.scheme is not ciphertext_1.scheme
    assert new_ciphertext_2.scheme is not ciphertext_2.scheme


def test_instances_from_security_param():
    paillier_scheme.boot_generation()
    paillier_scheme_floats.boot_generation()
    new_paillier_1 = Paillier.get_instance_from_sec_param(256)
    new_paillier_2 = Paillier.get_instance_from_sec_param(256)
    new_paillier_3 = Paillier.from_security_parameter(256)

    new_paillier_1.shut_down()
    new_paillier_2.shut_down()
    new_paillier_3.shut_down()
    paillier_scheme.shut_down()
    paillier_scheme_floats.shut_down()

    assert new_paillier_1 is new_paillier_2
    assert new_paillier_1 is not new_paillier_3
    assert new_paillier_2 is not new_paillier_3
    assert new_paillier_1 != new_paillier_3
    assert new_paillier_2 != new_paillier_3


async def send_and_receive(pool_http_2p, obj):
    # send from host 1 to host 2
    await pool_http_2p[0].send("local1", obj)
    item = await pool_http_2p[1].recv("local0")
    return item


@pytest.mark.asyncio
async def test_sending_and_receiving(pool_http_2p):
    """
    This test ensures that serialisation logic is correctly loading into the communication module
    """
    paillier_prime = await send_and_receive(pool_http_2p, paillier_scheme)
    assert paillier_prime == paillier_scheme

    encryption = paillier_scheme.encrypt(42)
    encryption_prime = await send_and_receive(pool_http_2p, encryption)
    assert encryption == encryption_prime

    pubkey_prime = await send_and_receive(pool_http_2p, paillier_scheme.public_key)
    assert paillier_scheme.public_key == pubkey_prime

    seckey_prime = await send_and_receive(pool_http_2p, paillier_scheme.secret_key)
    assert seckey_prime == paillier_scheme.secret_key
