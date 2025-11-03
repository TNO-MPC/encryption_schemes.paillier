"""
Implementation of the Asymmetric Encryption Scheme known as Paillier.
"""

from __future__ import annotations

import hashlib
import numbers
import sys
import typing
import warnings
from dataclasses import asdict, dataclass
from functools import cached_property, lru_cache, partial
from secrets import randbelow
from typing import Any, TypedDict, Union, cast, get_args

from tno.mpc.encryption_schemes.templates import (
    AdditiveHomomorphicCiphertext,
    AdditiveHomomorphicEncryptionScheme,
    AsymmetricEncryptionScheme,
    EncodedPlaintext,
    EncryptionSchemeWarning,
    PublicKey,
    RandomizedEncryptionSchemeWarning,
    SecretKey,
    SerializationError,
)
from tno.mpc.encryption_schemes.templates.exceptions import (
    WARN_INEFFICIENT_HOM_OPERATION,
)
from tno.mpc.encryption_schemes.utils import FixedPoint, mod_inv, pow_mod, randprime

if sys.version_info < (3, 11):
    from typing_extensions import NotRequired
else:
    from typing import NotRequired

# Check to see if the communication module is available
try:
    from tno.mpc.communication import RepetitionError, Serializer
    from tno.mpc.communication.packers import DeserializerOpts, SerializerOpts

    COMMUNICATION_INSTALLED = True
except ModuleNotFoundError:
    COMMUNICATION_INSTALLED = False
except ImportError as exc:
    raise ImportError(
        "Detected an incompatible version of 'tno.mpc.communication'. Please install this package with the extra 'communication', e.g. 'tno.mpc.encryption_schemes.paillier[communication]'."
    )


fxp = FixedPoint.fxp


WARN_UNFRESH_SERIALIZATION = (
    "Serializer identified and rerandomized a non-fresh ciphertext."
)


@dataclass(frozen=True, eq=True)
class PaillierPublicKey(PublicKey):
    r"""
    PublicKey for the Paillier encryption scheme.

    Constructs a new Paillier public key $(n, g)$, should have $n=pq$, with $p, q$ prime, and
    $g \in \mathbb{Z}^*_{n^2}$.

    :param n: Modulus $n$ of the plaintext space.
    :param g: Plaintext base $g$ for encryption.
    """

    n: int
    g: int

    @cached_property
    def n_squared(self) -> int:
        """
        Modulus of the ciphertext space.
        """
        return self.n**2

    @lru_cache
    def id(self) -> int:
        """
        Identifier of this specific key that is consistent over system architectures.

        :return: Representation of SHA-256 hash of object-defining attribute values.
        """
        # We use hashlib to ensure consistent hashes over different system architectures.
        h = hashlib.sha256()
        h.update(_to_bytes(self.n))
        h.update(_to_bytes(self.g))
        return int.from_bytes(h.digest(), "big")

    # region Serialization logic

    def serialize(self, _opts: SerializerOpts) -> dict[str, Any]:
        r"""
        Serialization function for public keys, which will be passed to the communication module.

        :raise SerializationError: When communication library is not installed.
        :return: Serialized version of this PaillierPublicKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return asdict(self)

    @staticmethod
    def deserialize(obj: dict[str, Any], _opts: DeserializerOpts) -> PaillierPublicKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module.

        :param obj: Serialized version of a PaillierPublicKey.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierPublicKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return PaillierPublicKey(**obj)

    # endregion


@dataclass(frozen=True, eq=True)
class PaillierSecretKey(SecretKey):
    r"""
    SecretKey for the Paillier encryption scheme.

    Constructs a new Paillier secret key $(\lambda, \mu)$, also contains $n$. Should have $n=pq$,
    with $p, q$ prime, $\lambda = \text{lcm}(p-1, q-1)$, and
    $\mu = (L(g^\lambda \mod n^2))^{-1} \mod n$, where $L(\cdot)$ is defined as $L(x) = (x-1)/n$.

    :param lambda_: Decryption exponent $\lambda$ of the ciphertext.
    :param mu: Decryption divisor $\mu$ for the ciphertext.
    :param n: Modulus $n$ of the plaintext space.
    """

    lambda_: int
    mu: int
    n: int

    # region Serialization logic

    def serialize(self, _opts: SerializerOpts) -> dict[str, Any]:
        r"""
        Serialization function for secret keys, which will be passed to the communication module.

        :raise SerializationError: When communication library is not installed.
        :return: Serialized version of this PaillierSecretKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return asdict(self)

    @staticmethod
    def deserialize(obj: dict[str, Any], _opts: DeserializerOpts) -> PaillierSecretKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module

        :param obj: Serialized version of a PaillierSecretKey.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierSecretKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return PaillierSecretKey(**obj)

    # endregion


Plaintext = Union[numbers.Integral, float, FixedPoint]


class PaillierCiphertext(AdditiveHomomorphicCiphertext[Plaintext, int, int]):
    """
    Ciphertext for the Paillier asymmetric encryption scheme. This ciphertext is rerandomizable
    and supports homomorphic operations.
    """

    scheme: Paillier

    def __init__(
        self: PaillierCiphertext,
        raw_value: int,
        scheme: Paillier,
        *,
        fresh: bool = False,
    ):
        r"""
        Construct a RandomizableCiphertext, with the given value for the given EncryptionScheme.

        :param raw_value: PaillierCiphertext value $c \in \mathbb{Z}_{n^2}$.
        :param scheme: Paillier scheme that is used to encrypt this ciphertext.
        :param fresh: Indicates whether fresh randomness is already applied to the raw_value.
        :raise TypeError: When the given scheme is not a Paillier scheme.
        """

        if not isinstance(scheme, Paillier):
            raise TypeError(f"expected Paillier scheme, got {type(scheme)}")
        super().__init__(raw_value, scheme, fresh=fresh)

    def apply_randomness(self: PaillierCiphertext, randomization_value: int) -> None:
        """
        Rerandomize this ciphertext using the given random value.

        :param randomization_value: Random value used for rerandomization.
        """
        modulus = self.scheme.public_key.n_squared
        self._raw_value *= randomization_value
        self._raw_value %= modulus

    def __eq__(self, other: object) -> bool:
        """
        Compare this PaillierCiphertext with another to determine (in)equality.

        :param other: Object to compare this PaillierCiphertext with.
        :raise TypeError: When other object is not a PaillierCiphertext.
        :return: Boolean value representing (in)equality of both objects.
        """
        if not isinstance(other, PaillierCiphertext):
            return NotImplemented
        return self._raw_value == other._raw_value and self.scheme == other.scheme

    def copy(self: PaillierCiphertext) -> PaillierCiphertext:
        """
        Create a copy of this Ciphertext, with the same value and scheme. The copy is not
        randomized and is considered not fresh.

        :return: Copied PaillierCiphertext.
        """
        return PaillierCiphertext(raw_value=self._raw_value, scheme=self.scheme)

    # region Serialization logic

    class SerializedPaillierCiphertext(TypedDict):
        value: int
        scheme_id: int

    def serialize(
        self, _opts: SerializerOpts
    ) -> PaillierCiphertext.SerializedPaillierCiphertext:
        r"""
        Serialization function for Paillier ciphertexts, which will be passed to the communication
        module.

        If the ciphertext is not fresh, it is randomized before serialization. After serialization,
        it is always marked as not fresh for security reasons.

        :raise SerializationError: When communication library is not installed.
        :return: Serialized version of this PaillierCiphertext.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if not self.fresh:
            warnings.warn(
                WARN_UNFRESH_SERIALIZATION,
                RandomizedEncryptionSchemeWarning,
                stacklevel=2,
            )
            self.randomize()
        self._fresh = False
        return {
            "value": self._raw_value,
            "scheme_id": self.scheme.identifier,
        }

    @staticmethod
    def deserialize(
        obj: PaillierCiphertext.SerializedPaillierCiphertext,
        _opts: DeserializerOpts,
    ) -> PaillierCiphertext:
        r"""
        Deserialization function for Paillier ciphertexts, which will be passed to the
        communication module.

        :param obj: Serialized version of a PaillierCiphertext.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierCiphertext from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        try:
            scheme = Paillier.from_id(obj["scheme_id"])
        except KeyError as exc:
            raise SerializationError(
                "The scheme that is associated with the provided serialized PaillierCiphertext is not known. Please ensure that the corresponding scheme is deserialized first."
            ) from exc
        return PaillierCiphertext(
            raw_value=obj["value"],
            scheme=scheme,
        )

    # endregion


class Paillier(
    AsymmetricEncryptionScheme[
        PaillierPublicKey,
        PaillierSecretKey,
        Plaintext,
        int,
        PaillierCiphertext,
    ],
    AdditiveHomomorphicEncryptionScheme[
        tuple[PaillierPublicKey, PaillierSecretKey],
        Plaintext,
        int,
        PaillierCiphertext,
        int,
    ],
):
    """
    Paillier Encryption Scheme. This is an AsymmetricEncryptionScheme, with a public and secret key.
    This is also a AdditiveHomomorphicEncryptionScheme, thus having internal randomness generation,
    allowing for the use of precomputed randomness, and support for addition of ciphertexts.
    """

    public_key: PaillierPublicKey
    secret_key: PaillierSecretKey

    def __init__(
        self,
        public_key: PaillierPublicKey,
        secret_key: PaillierSecretKey | None,
        precision: int = 0,
        share_secret_key: bool = False,
        debug: bool = False,
    ):
        """
        Construct a new Paillier encryption scheme, with the given keypair, randomness object,
        precision for fixed point encryption.

        :param public_key: Public key for this Paillier Scheme.
        :param secret_key: Secret Key for this Paillier Scheme.
        :param precision: Fixed point precision of this encoding, in decimal places.
        :param share_secret_key: Boolean value stating whether or not the secret key should be
            included in serialization. This should only be set to True if one is really sure of it.
        :param debug: flag to determine whether debug information should be displayed.
        """
        self._generate_randomness = partial(  # type: ignore[method-assign]
            self._generate_randomness_from_args,
            public_n=public_key.n,
            public_n_squared=public_key.n_squared,
        )
        AsymmetricEncryptionScheme.__init__(
            self, public_key=public_key, secret_key=secret_key
        )
        AdditiveHomomorphicEncryptionScheme.__init__(
            self,
            debug=debug,
        )

        self.precision = precision
        self.max_value = FixedPoint(public_key.n // 2, precision=precision)
        self.min_value = -self.max_value

        # Variable that determines whether a secret key is sent when the scheme is sent
        # over a communication channel
        self.share_secret_key = share_secret_key

        if self.identifier not in self._instances:
            self.save_globally()

    @staticmethod
    def generate_key_material(
        key_length: int,
    ) -> tuple[
        PaillierPublicKey, PaillierSecretKey
    ]:  # pylint: disable=arguments-differ
        r"""
        Method to generate key material (PaillierPublicKey and PaillierPrivateKey).

        :param key_length: Bit length of the public key $n$.
        :return: Tuple with first the Public Key and then the Secret Key.
        """

        p = 1
        q = 1
        n = p * q
        while n.bit_length() != key_length:
            p = randprime(2 ** (key_length // 2 - 1), 2 ** (key_length // 2))
            q = randprime(2 ** (key_length // 2 - 1), 2 ** (key_length // 2))
            while p == q:
                q = randprime(2 ** (key_length // 2 - 1), 2 ** (key_length // 2))
            n = p * q
        lambda_ = (p - 1) * (q - 1)
        g = n + 1
        mu = mod_inv(lambda_, n)  # use g = n + 1
        # mu = mod_inv(Paillier.func_l(pow(g, lambda_, n**2), n), n)  # use random g
        return PaillierPublicKey(n, g), PaillierSecretKey(lambda_, mu, n)

    def encode(self, plaintext: Plaintext) -> EncodedPlaintext[int]:
        """
        Encode a float or int with the given precision of this instantiation. Allows for positive
        and negative numbers.

        :param plaintext: Plaintext to be encoded.
        :raise ValueError: If the plaintext is outside the supported range of this Paillier
            instance.
        :return: EncodedPlaintext object containing the encoded value.
        """
        if not self.min_value <= plaintext <= self.max_value:
            raise ValueError(
                f"This encoding scheme only supports values in the range [{self.min_value};"
                f"{self.max_value}], {plaintext} is outside that range."
            )
        plaintext_fxp = fxp(plaintext, self.precision)
        return EncodedPlaintext(plaintext_fxp.value, self)

    def decode(self, encoded_plaintext: EncodedPlaintext[int]) -> Plaintext:
        """
        Decode an EncodedPlaintext given the specified precision of this instantiation.

        :param encoded_plaintext: Plaintext to be decoded.
        :return: decoded Plaintext value
        """
        value = (
            encoded_plaintext.value
            if 2 * encoded_plaintext.value <= self.public_key.n
            else encoded_plaintext.value - self.public_key.n
        )
        return FixedPoint(value, self.precision)

    def _unsafe_encrypt_raw(
        self,
        plaintext: EncodedPlaintext[int],
    ) -> PaillierCiphertext:
        r"""
        Encrypts an encoded (raw) plaintext value, but does not apply randomization. Given a raw
        plaintext message $m \in \mathbb{Z}_n$, we compute the ciphertext value as
        $c = g^m \mod n^2$.

        :param plaintext: EncodedPlaintext object containing the raw value $m \in \mathbb{Z}_n$
            to be encrypted.
        :return: Non-randomized PaillierCiphertext object containing the encrypted plaintext $c$.
        """
        return PaillierCiphertext(
            1 + plaintext.value * self.public_key.n, self
        )  # use g = n + 1

    def _decrypt_raw(self, ciphertext: PaillierCiphertext) -> EncodedPlaintext[int]:
        r"""
        Decrypts an ciphertext to its encoded plaintext value. Given a ciphertext
        $c \in \mathbb{Z}^*_{n^2}$, we compute the raw plaintext message as
        $m = L(c^\lambda \mod n^2) \cdot \mu \mod n.

        :param ciphertext: PaillierCiphertext object containing the ciphertext $c$ to be decrypted.
        :return: EncodedPlaintext object containing the encoded decryption $m$ of the ciphertext.
        """
        c = ciphertext.peek_value()
        c_lambda = pow_mod(c, self.secret_key.lambda_, self.public_key.n_squared)
        m = Paillier.func_l(c_lambda, self.secret_key.n)
        m *= self.secret_key.mu
        m %= self.secret_key.n
        return EncodedPlaintext(m, self)

    def neg(self, ciphertext: PaillierCiphertext) -> PaillierCiphertext:
        r"""
        Negate the underlying plaintext of this ciphertext.

        If the original plaintext of this ciphertext was 5. this method returns the ciphertext that
        has -5 as underlying plaintext. Given a ciphertext $c$ we compute the negated ciphertext
        $c'$ such that $c \cdot c' = 1 \mod n^2$.

        The resulting ciphertext is fresh only if the input was fresh. The input is marked as
        non-fresh after the operation.

        :param ciphertext: PaillierCiphertext $c$ of which the underlying plaintext should be
            negated.
        :return: PaillierCiphertext $c'$ corresponding to the negated plaintext.
        """
        if new_ciphertext_fresh := ciphertext.fresh:
            warnings.warn(
                WARN_INEFFICIENT_HOM_OPERATION,
                RandomizedEncryptionSchemeWarning,
                stacklevel=2,
            )

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return PaillierCiphertext(
            mod_inv(ciphertext.get_value(), self.public_key.n_squared),
            self,
            fresh=new_ciphertext_fresh,
        )

    def add(
        self,
        ciphertext: PaillierCiphertext,
        other: PaillierCiphertext | Plaintext,
    ) -> PaillierCiphertext:
        r"""
        Secure addition.

        If other is another PaillierCiphertext $c_2$, add the underlying plaintext value of
        ciphertext $c_1$ with the underlying plaintext value of other. If it is a
        Plaintext, we add the plaintext value $m_2$ to ciphertext, by first encryption it and
        obtaining $c_2 = Enc(m_2)$. We then compute the result as $c' = c_1 \cdot c_2 \mod n^2$.

        The resulting ciphertext is fresh only if at least one of the inputs was fresh. Both inputs
        are marked as non-fresh after the operation.

        :param ciphertext: First PaillierCiphertext $c_1$ of which the underlying plaintext is
            added.
        :param other: Either a second PaillierCiphertext $c_2$ of which the underlying
            plaintext is added to the first. Or a plaintext $m_2$ that is added to the underlying
            plaintext of the first.
        :raise TypeError: When other is a ciphertext with a different scheme than ciphertext.
        :return: A PaillierCiphertext $c'$ containing the encryption of the addition of both values.
        """
        if isinstance(other, get_args(Plaintext)):
            other = self.unsafe_encrypt(cast(Plaintext, other))
        elif ciphertext.scheme != cast(PaillierCiphertext, other).scheme:
            raise TypeError(
                "The scheme of your first ciphertext is not equal to the scheme of your second "
                "ciphertext."
            )
        other = cast(PaillierCiphertext, other)

        if new_ciphertext_fresh := ciphertext.fresh or other.fresh:
            warnings.warn(
                WARN_INEFFICIENT_HOM_OPERATION,
                RandomizedEncryptionSchemeWarning,
                stacklevel=2,
            )

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return PaillierCiphertext(
            ciphertext.get_value() * other.get_value() % self.public_key.n_squared,
            self,
            fresh=new_ciphertext_fresh,
        )

    def mul(
        self, ciphertext: PaillierCiphertext, other: PaillierCiphertext | Plaintext
    ) -> PaillierCiphertext:
        """
        Multiply the underlying plaintext value of ciph $c$ with the given scalar $s$.

        We obtain the result by computing $c' = c^s$.

        The resulting ciphertext is fresh only if the input was fresh. The input is marked as
        non-fresh after the operation.

        :param ciphertext: PaillierCiphertext $c$ of which the underlying plaintext is multiplied.
        :param other: A scalar $s$ with which the plaintext underlying ciph should be
            multiplied.
        :raise NotImplementedError: When other is not an integer.
        :return: PaillierCiphertext $c'$ containing the encryption of the product of both values.
        """
        # This check is necessary to support both built-in integers and gmpy2 integers
        # - The mpz class from gmpy2 is registered as a virtual subclass of numbers.Integral. Static type checkers
        #   do not understand such dynamic typing constructions, so the stubs define mpz as a subclass of int, but
        #   the runtime check is done on `numbers.Integral`.
        if not isinstance(other, numbers.Integral):
            raise NotImplementedError(
                f"Type of scalar (second multiplicand) should be an integer and not"
                f" {type(other)}."
            )
        if (other := cast(int, other)) < 0:
            ciphertext = self.neg(ciphertext)
            other = -other

        if new_ciphertext_fresh := ciphertext.fresh:
            warnings.warn(
                WARN_INEFFICIENT_HOM_OPERATION,
                RandomizedEncryptionSchemeWarning,
                stacklevel=2,
            )

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return PaillierCiphertext(
            pow_mod(ciphertext.get_value(), other, self.public_key.n_squared),
            self,
            fresh=new_ciphertext_fresh,
        )

    def __eq__(self, other: object) -> bool:
        """
        Compare this Paillier scheme with another to determine (in)equality. Does not take the
        secret key into account as it might not be known and the public key combined with the
        precision should be sufficient to determine equality.

        :param other: Object to compare this Paillier scheme with.
        :return: Boolean value representing (in)equality of both objects.
        """
        if not isinstance(other, Paillier):
            return NotImplemented
        return self.identifier == other.identifier

    def __hash__(self) -> int:
        """
        Hash this Paillier scheme.

        :return: Hash of this Paillier scheme.
        """
        return hash((self.public_key, self.precision))

    @staticmethod
    def _generate_randomness_from_args(
        public_n: int, public_n_squared: int | None = None
    ) -> int:
        r"""
        Method to generate randomness value $r^n \mod n^2$, from a random number
        $r \in_R \mathbb{Z}^*_{n}$ for Paillier.

        :param public_n: Modulus of the message space.
        :param public_n_squared: Square of public_n. Can be passed for efficiency reasons.
        :return: A random number.
        """
        if not public_n_squared:
            public_n_squared = public_n**2
        random_element = randbelow(public_n - 1) + 1
        return pow_mod(random_element, public_n, public_n_squared)

    def random_plaintext(
        self,
        lower_bound: Plaintext | None = None,
        upper_bound: Plaintext | None = None,
    ) -> FixedPoint:
        """
        Generate a uniformly random plaintext from the given interval.

        :param lower_bound: Lower bound (inclusive), when no lower bound is given, the lowest value of the plaintext
            space is used.
        :param upper_bound: Upper bound (exclusive), when no lower bound is given, the first value that is higher than
            the maximum value of the plaintext space is used.
        :raise Warning: When the precision of `lower_bound` or `upper_bound` is larger than `self.precision`.
        :raise ValueError: When an interval larger than plaintext space or an empty interval is specified.
        :return: A uniformly random element from specified range represented as a fixed point number
            If range unspecified, yields a uniformly random fixed point number from plaintext space.
        """

        if lower_bound is None:
            lower_bound = self.min_value
        if upper_bound is None:
            upper_bound = self.max_value + 10 ** (-self.precision)

        # scale upper bounds to the right precision
        lower_bound_scaled = fxp(lower_bound, target_precision=self.precision)
        upper_bound_scaled = fxp(upper_bound, target_precision=self.precision)

        # perform some checks on the bounds
        if lower_bound_scaled >= upper_bound_scaled:
            raise ValueError(
                f"The entered interval [{lower_bound_scaled}, {upper_bound_scaled}) is empty when trimmed to "
                f"{self.precision} decimals. Please enter a non-empty interval."
            )
        if (
            lower_bound_scaled < self.min_value
            or upper_bound_scaled > self.max_value + 10 ** (-self.precision)
        ):
            raise ValueError(
                f"This encoding scheme only supports values in the range [{self.min_value};"
                f"{self.max_value}]. Part of [{lower_bound_scaled}; {upper_bound_scaled}) is outside that range."
            )

        if fxp(lower_bound).precision > self.precision:
            warnings.warn(
                EncryptionSchemeWarning(
                    "The lower bound has more decimals than the precision of the scheme."
                )
            )
        if fxp(upper_bound).precision > self.precision:
            warnings.warn(
                EncryptionSchemeWarning(
                    "The upper bound has more decimals than the precision of the scheme."
                )
            )

        return FixedPoint.random_range(lower_bound_scaled, upper_bound_scaled)

    def sample_mask(
        self,
        lower_bound: Plaintext,
        upper_bound: Plaintext,
        security_level: int | None = None,
    ) -> FixedPoint:
        r"""
        Returns a random value to mask a plaintext message from a given message space of size $|M|$ with statistical
        security, given security parameter $\sigma$. The result will be a random mask from an interval with size
        $|M| \cdot 2^{\sigma}$ that is centered around 0.
        To read the mathematics and reasoning behind this, please take a look at the README.

        :param lower_bound: Integral lower bound for message space (inclusive).
        :param upper_bound: Integral upper bound for message space (exclusive).
        :param security_level: Security level $\sigma$ we require from additive masking, if `None` a mask with perfect
            security is returned. The security level should be a non-negative integer, denoting the number of bits
            of security.
        :raise Warning: When the precision of `lower_bound` or `upper_bound` is larger than `self.precision`. A warning
            is also returned when the chosen security level equals 0 (since that provides NO security).
        :raise ValueError: When an interval larger than plaintext space or an empty interval is specified or when an
            invalid security level is given.
        :return: A random fixed point number (with statistical security) to be used for masking.
        """
        if security_level is not None and security_level < 0:
            raise ValueError(
                f"Security level has value {security_level} this is not supported. It should be either a"
                f" non-negative integer or `None`"
            )

        # check precision of bounds
        if fxp(lower_bound).precision > self.precision:
            warnings.warn(
                EncryptionSchemeWarning(
                    "The lower bound has more decimals than the precision of the scheme."
                )
            )
        if fxp(upper_bound).precision > self.precision:
            warnings.warn(
                EncryptionSchemeWarning(
                    "The upper bound has more decimals than the precision of the scheme."
                )
            )

        # handle security_level None or 0.
        if security_level is None:
            return self.random_plaintext()
        if security_level == 0:
            warnings.warn(
                EncryptionSchemeWarning(
                    "The used security level provides NO security. The returned mask will always be 0."
                )
            )
            return fxp(0, target_precision=self.precision)

        # scale upper bounds to the right precision
        lower_bound_scaled = fxp(lower_bound, target_precision=self.precision)
        upper_bound_scaled = fxp(upper_bound, target_precision=self.precision)

        # we create an interval of size interval_size * 2**(security_level)
        interval_size = upper_bound_scaled - lower_bound_scaled
        secure_upper_bound = interval_size << (security_level - 1)
        return self.random_plaintext(-secure_upper_bound, secure_upper_bound)

    @staticmethod
    def func_l(input_x: int, n: int) -> int:
        r"""
        Paillier specific $L(\cdot)$ function: $L(x) = (x-1)/n$.

        :param input_x: input $x$
        :param n: input $n$ (public key modulus)
        :return: value of $L(x) = (x-1)/n$.
        """
        return (input_x - 1) // n

    @classmethod
    def id_from_arguments(
        cls,
        public_key: PaillierPublicKey,
        precision: int = 0,
    ) -> int:
        """
        Method that turns the arguments for the constructor into an identifier. This identifier is
        used to find constructor calls that would result in identical schemes.

        :param public_key: PaillierPublicKey of the Paillier instance.
        :param precision: Precision of the Paillier instance
        :return: Identifier of the Paillier instance
        """
        # We use hashlib to ensure consistent hashes over different system architectures.
        h = hashlib.sha256()
        pk_id = public_key.id()
        h.update(pk_id.to_bytes(256 // 8, "big"))
        h.update(_to_bytes(precision))
        return int.from_bytes(h.digest(), "big")

    # region Serialization logic

    class SerializedPaillier(TypedDict):
        prec: int
        pubkey: PaillierPublicKey
        seckey: NotRequired[PaillierSecretKey]

    def serialize(self, _opts: SerializerOpts) -> Paillier.SerializedPaillier:
        r"""
        Serialization function for Paillier schemes, which will be passed to the communication
        module. The sharing of the secret key depends on the attribute share_secret_key.

        :raise SerializationError: When communication library is not installed.
        :return: Serialized version of this Paillier scheme.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if self.share_secret_key:
            return self.serialize_with_secret_key()
        return self.serialize_without_secret_key()

    def serialize_with_secret_key(
        self,
    ) -> Paillier.SerializedPaillier:
        """
        Serialization function for Paillier schemes, that does include the secret key.

        :raise SerializationError: When communication library is not installed.
        :return: Serialized version of this Paillier scheme.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "prec": self.precision,
            "pubkey": self.public_key,
            "seckey": self.secret_key,
        }

    def serialize_without_secret_key(self) -> Paillier.SerializedPaillier:
        """
        Serialization function for Paillier schemes, that does not include the secret key.

        :raise SerializationError: When communication library is not installed.
        :return: Serialized version of this Paillier scheme (without the secret key).
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "prec": self.precision,
            "pubkey": self.public_key,
        }

    @staticmethod
    def deserialize(
        obj: Paillier.SerializedPaillier,
        _opts: DeserializerOpts,
    ) -> Paillier:
        r"""
        Deserialization function for Paillier schemes, which will be passed to
        the communication module.

        :param obj: Serialized version of a Paillier scheme.
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized Paillier scheme from the given dict. Might not have a secret
            key when that was not included in the received serialization.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        pubkey = obj["pubkey"]
        precision = obj["prec"]
        # This piece of code is specifically used for the case where sending and receiving
        # happens between hosts running the same python instance (local network).
        # In this case, the Paillier scheme that was sent is already available before it
        # arrives and does not need to be created anymore.
        identifier = Paillier.id_from_arguments(public_key=pubkey, precision=precision)
        if identifier in Paillier._instances:
            paillier = Paillier.from_id(identifier)
        else:
            paillier = Paillier(
                public_key=pubkey,
                secret_key=obj["seckey"] if "seckey" in obj else None,
                precision=precision,
            )
        return paillier

    # endregion


def _to_bytes(n: typing.SupportsInt) -> bytes:
    """
    Unidirectional conversion from numbers.Integral to bytes.

    :param n: Integer to convert.
    :return: Byte representation of provided input.
    """
    from tno.mpc.encryption_schemes.utils import USE_GMPY2

    if USE_GMPY2:
        import gmpy2

        if isinstance(n, gmpy2.mpz):
            return gmpy2.to_binary(n)
    n_int = int(n)
    return n_int.to_bytes(n_int.bit_length() // 8 + 1, "little")


if COMMUNICATION_INSTALLED:
    try:
        Serializer.register_class(Paillier)
        Serializer.register_class(PaillierCiphertext)
        Serializer.register_class(PaillierPublicKey)
        Serializer.register_class(PaillierSecretKey)
    except RepetitionError:
        pass
