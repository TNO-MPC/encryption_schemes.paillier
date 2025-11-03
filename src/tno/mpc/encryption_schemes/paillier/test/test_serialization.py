"""
This module tests the serialization of Paillier instances.
"""

from __future__ import annotations

from typing import TypeVar

import pytest

from tno.mpc.communication import SupportsSerialization
from tno.mpc.communication.packers import DefaultDeserializerOpts, DefaultSerializerOpts
from tno.mpc.encryption_schemes.templates import (
    RandomizedEncryptionSchemeWarning,
    SerializationError,
)

from tno.mpc.encryption_schemes.paillier import (
    Paillier,
    PaillierCiphertext,
    PaillierPublicKey,
    PaillierSecretKey,
)
from tno.mpc.encryption_schemes.paillier.paillier import WARN_UNFRESH_SERIALIZATION

SupportsSerializationT = TypeVar("SupportsSerializationT", bound=SupportsSerialization)


def serialize_deserialize(obj: SupportsSerializationT) -> SupportsSerializationT:
    """
    Serialize and deserialize an object.

    :param obj: Object to be serialized and deserialized.
    :return: Resulting object.
    """
    return obj.deserialize(  # type: ignore[return-value]
        obj.serialize(DefaultSerializerOpts), DefaultDeserializerOpts
    )


def test_serialization_public_key_produces_equal_key() -> None:
    """
    Test to determine whether the public key serialization works properly.
    """
    public_key = PaillierPublicKey(n=10, g=20)
    public_key_prime = serialize_deserialize(public_key)
    assert public_key == public_key_prime


def test_serialization_secret_key_produces_equal_key() -> None:
    """
    Test to determine whether the secret key serialization works properly.
    """
    secret_key = PaillierSecretKey(lambda_=10, mu=20, n=30)
    secret_key_prime = serialize_deserialize(secret_key)
    assert secret_key == secret_key_prime


def deserialize_paillier_scheme(
    scheme_serialized: Paillier.SerializedPaillier,
) -> Paillier:
    """
    Deserialize a paillier scheme and ensure that a new instance is created.

    :param scheme_serialized: Serialized Paillier scheme.
    :return: Deserialized Paillier scheme, which is guaranteed to be a new object.
    """
    # By clearing Paillier._instances, we ensure that a new Paillier object is created during
    # deserialization. Otherwise, Paillier recognises a known scheme and returns that known object
    # (with its secret key) instead.
    try:
        instances = Paillier._instances
        Paillier.clear_instances()
        return Paillier.deserialize(scheme_serialized, DefaultDeserializerOpts)
    finally:
        Paillier._instances = instances  # type: ignore[assignment]


def test_serialization_paillier_scheme_produces_equal_scheme(
    paillier_scheme_with_precision: Paillier,
) -> None:
    """
    Test serialization of the paillier scheme with secret key.

    :param paillier_scheme_with_precision: Scheme under test.
    """
    scheme_serialized = paillier_scheme_with_precision.serialize(DefaultSerializerOpts)
    scheme_prime = deserialize_paillier_scheme(scheme_serialized)

    assert paillier_scheme_with_precision == scheme_prime
    assert not paillier_scheme_with_precision is scheme_prime


def test_serialization_paillier_scheme_excludes_secret_key(
    paillier_scheme_with_precision: Paillier,
) -> None:
    """
    Ensure that, by default, serialization of the paillier scheme excludes the secret key.

    :param paillier_scheme_with_precision: Scheme under test.
    """
    scheme_serialized = paillier_scheme_with_precision.serialize(DefaultSerializerOpts)
    scheme_prime = deserialize_paillier_scheme(scheme_serialized)

    assert scheme_prime.secret_key is None


def test_serialization_paillier_scheme_with_secret_key(
    paillier_scheme_with_precision: Paillier,
) -> None:
    """
    Test serialization of the paillier scheme with secret key.

    :param paillier_scheme_with_precision: Scheme under test.
    """
    scheme = Paillier(
        paillier_scheme_with_precision.public_key,
        paillier_scheme_with_precision.secret_key,
        share_secret_key=True,
    )
    scheme.shut_down()
    scheme_prime = deserialize_paillier_scheme(scheme.serialize(DefaultSerializerOpts))

    assert isinstance(scheme_prime.secret_key, PaillierSecretKey)


def test_serialization_ciphertext_produces_equal_ciphertext(
    ciphertext: PaillierCiphertext,
) -> None:
    """
    Test to determine whether the ciphertext serialization works properly.

    :param ciphertext: Ciphertext under test.
    """
    ciphertext_prime = serialize_deserialize(ciphertext)
    assert ciphertext == ciphertext_prime


@pytest.mark.parametrize("fresh", [True, False])
def test_serialization_ciphertext_sets_original_ciphertext_unfresh(
    ciphertext: PaillierCiphertext, fresh: bool
) -> None:
    """
    Test to determine whether the ciphertext serialization makes the original ciphertext unfresh.

    :param ciphertext: Ciphertext under test.
    :param fresh: Freshness of the ciphertext under test.
    """
    ciphertext._fresh = fresh
    ciphertext.serialize(DefaultSerializerOpts)
    assert not ciphertext.fresh


def test_deserialized_ciphertext_is_unfresh(ciphertext: PaillierCiphertext) -> None:
    """
    Test to determine whether a deserialized ciphertext is unfresh.

    :param ciphertext: Ciphertext under test.
    """
    ciphertext_prime = serialize_deserialize(ciphertext)
    assert not ciphertext_prime.fresh


def test_serialization_unfresh_ciphertext_triggers_randomization(
    ciphertext: PaillierCiphertext,
) -> None:
    """
    Test that serialization of an unfresh ciphertext triggers randomization of that ciphertext.

    :param ciphertext: Ciphertext under test.
    """
    original_raw_value = ciphertext.peek_value()
    ciphertext._fresh = False
    ciphertext_serialized = ciphertext.serialize(DefaultSerializerOpts)
    assert original_raw_value != ciphertext_serialized["value"]


def test_serialization_unfresh_ciphertext_raises_warning(
    ciphertext: PaillierCiphertext,
) -> None:
    """
    Test that serialization of an unfresh ciphertext raises a warning.

    :param ciphertext: Ciphertext under test.
    """
    ciphertext._fresh = False
    with pytest.warns(
        RandomizedEncryptionSchemeWarning, match=WARN_UNFRESH_SERIALIZATION
    ):
        ciphertext.serialize(DefaultSerializerOpts)


def test_deserialization_ciphertext_with_unknown_scheme_throws_serializationerror() -> (
    None
):
    """
    Test that ciphertext deserialization with unknown scheme throws the appropriate error.
    """
    scheme = Paillier.from_security_parameter(key_length=16)
    scheme.shut_down()
    ciphertext = scheme.encrypt(0)

    # Ensure scheme is not registered
    scheme._instances.pop(scheme.identifier)

    serialized_ciphertext = ciphertext.serialize(DefaultSerializerOpts)
    with pytest.raises(SerializationError):
        PaillierCiphertext.deserialize(serialized_ciphertext, DefaultDeserializerOpts)
