"""
Implementation of the Asymmetric Encryption Scheme known as Paillier.
"""

from __future__ import annotations

import numbers
import sys
import warnings
from functools import partial
from secrets import randbelow
from typing import Any, Tuple, Union, cast

from tno.mpc.encryption_schemes.templates import (
    AsymmetricEncryptionScheme,
    EncodedPlaintext,
    EncryptionSchemeWarning,
    PublicKey,
    RandomizableCiphertext,
    RandomizedEncryptionScheme,
    SecretKey,
    SerializationError,
)
from tno.mpc.encryption_schemes.utils import FixedPoint, mod_inv, pow_mod, randprime

# Check to see if the communication module is available
try:
    from tno.mpc.communication import RepetitionError, Serialization
    from tno.mpc.communication.httphandlers import HTTPClient

    COMMUNICATION_INSTALLED = True
except ModuleNotFoundError:
    COMMUNICATION_INSTALLED = False

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict, get_args
else:
    from typing import TypedDict, get_args

fxp = FixedPoint.fxp

WARN_INEFFICIENT_HOM_OPERATION = (
    "Identified a fresh ciphertext as input to a homomorphic operation, which is no longer fresh "
    "after the operation. This indicates a potential inefficiency if the non-fresh input may also "
    "be used in other operations (unused randomness). Solution: randomize ciphertexts as late as "
    "possible, e.g. by encrypting them with scheme.unsafe_encrypt and randomizing them just "
    "before sending. Note that the serializer randomizes non-fresh ciphertexts by default."
)
WARN_UNFRESH_SERIALIZATION = (
    "Serializer identified and rerandomized a non-fresh ciphertext."
)


class PaillierPublicKey(PublicKey):
    """
    PublicKey for the Paillier encryption scheme.
    """

    def __init__(self, n: int, g: int):
        r"""
        Constructs a new Paillier public key $(n, g)$, should have $n=pq$, with $p, q$ prime, and
        $g \in \mathbb{Z}^*_{n^2}$.

        :param n: Modulus $n$ of the plaintext space.
        :param g: Plaintext base $g$ for encryption.

        Also contains:
        n_squared: Modulus of the ciphertext space $n^2$.
        """
        super().__init__()
        self.n = n
        self.n_squared = n**2
        self.g = g

    def __hash__(self) -> int:
        """
        Compute a hash from this PaillierPublicKey instance.

        :return: Hash value.
        """
        return hash((self.n, self.g))

    def __eq__(self, other: object) -> bool:
        """
        Compare this PaillierPublicKey with another to determine (in)equality.

        :param other: Object to compare this PaillierPublicKey with.
        :raise TypeError: When other object is not a PaillierPublicKey.
        :return: Boolean value representing (in)equality of both objects.
        """
        if not isinstance(other, PaillierPublicKey):
            raise TypeError(
                f"Expected comparison with another PaillierPublicKey, not {type(other)}"
            )
        return self.n == other.n and self.g == other.g

    def __str__(self) -> str:
        """
        :return: Reprentation of public key prepended by (n, g)=
        """
        return f"(n, g)=({self.n}, {self.g})"

    # region Serialization logic

    class SerializedPaillierPublicKey(TypedDict):
        n: int
        g: int

    def serialize(
        self, **_kwargs: Any
    ) -> PaillierPublicKey.SerializedPaillierPublicKey:
        r"""
        Serialization function for public keys, which will be passed to the communication module.

        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this PaillierPublicKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "n": self.n,
            "g": self.g,
        }

    @staticmethod
    def deserialize(
        obj: PaillierPublicKey.SerializedPaillierPublicKey, **_kwargs: Any
    ) -> PaillierPublicKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module.

        :param obj: serialized version of a PaillierPublicKey.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierPublicKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return PaillierPublicKey(
            n=obj["n"],
            g=obj["g"],
        )

    # endregion


class PaillierSecretKey(SecretKey):
    """
    SecretKey for the Paillier encryption scheme.
    """

    def __init__(self, lambda_value: int, mu: int, n: int):
        r"""
        Constructs a new Paillier secret key $(\lambda, \mu)$, also contains $n$.
        Should have $n=pq$, with $p, q$ prime, $\lambda = \text{lcm}(p-1, q-1)$, and
        $\mu = (L(g^\lambda \mod n^2))^{-1} \mod n$, where $L(\cdot)$ is defined as
        $L(x) = (x-1)/n$.

        :param lambda_value: Decryption exponent $\lambda$ of the ciphertext.
        :param mu: Decryption divisor $\mu$ for the ciphertext.
        :param n: Modulus $n$ of the plaintext space.
        """
        super().__init__()
        self.lambda_ = lambda_value
        self.mu = mu
        self.n = n

    def __hash__(self) -> int:
        """
        Compute a hash from this PaillierSecretKey instance.

        :return: Hash value.
        """
        return hash((self.lambda_, self.mu, self.n))

    def __eq__(self, other: object) -> bool:
        """
        Compare this PaillierSecretKey with another to determine (in)equality.

        :param other: Object to compare this PaillierSecretKey with.
        :raise TypeError: When other object is not a PaillierSecretKey.
        :return: Boolean value representing (in)equality of both objects.
        """
        if not isinstance(other, PaillierSecretKey):
            raise TypeError(
                f"Expected comparison with another PaillierSecretKey, not {type(other)}"
            )
        return (
            self.lambda_ == other.lambda_ and self.mu == other.mu and self.n == other.n
        )

    def __str__(self) -> str:
        """
        :return: Reprentation of secret key prepended by (lambda, mu)=
        """
        return f"(lambda, mu)=({self.lambda_}, {self.mu})"

    # region Serialization logic

    class SerializedPaillierSecretKey(TypedDict):
        lambda_: int
        mu: int
        n: int

    def serialize(
        self, **_kwargs: Any
    ) -> PaillierSecretKey.SerializedPaillierSecretKey:
        r"""
        Serialization function for secret keys, which will be passed to the communication module.

        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this PaillierSecretKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "lambda_": self.lambda_,
            "mu": self.mu,
            "n": self.n,
        }

    @staticmethod
    def deserialize(
        obj: PaillierSecretKey.SerializedPaillierSecretKey, **_kwargs: Any
    ) -> PaillierSecretKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module

        :param obj:  serialized version of a PaillierSecretKey.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierSecretKey from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return PaillierSecretKey(
            lambda_value=obj["lambda_"],
            mu=obj["mu"],
            n=obj["n"],
        )

    # endregion


KeyMaterial = Tuple[PaillierPublicKey, PaillierSecretKey]
Plaintext = Union[numbers.Integral, float, FixedPoint]


class PaillierCiphertext(RandomizableCiphertext[KeyMaterial, Plaintext, int, int, int]):
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
            raise TypeError(
                f"Expected comparison with another PaillierCiphertext, not {type(other)}"
            )
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
        scheme: Paillier

    def serialize(
        self, **_kwargs: Any
    ) -> PaillierCiphertext.SerializedPaillierCiphertext:
        r"""
        Serialization function for Paillier ciphertexts, which will be passed to the communication
        module.

        If the ciphertext is not fresh, it is randomized before serialization. After serialization,
        it is always marked as not fresh for security reasons.

        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this PaillierCiphertext.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if not self.fresh:
            warnings.warn(
                WARN_UNFRESH_SERIALIZATION, EncryptionSchemeWarning, stacklevel=2
            )
            self.randomize()
        self._fresh = False
        return {
            "value": self._raw_value,
            "scheme": self.scheme,
        }

    @staticmethod
    def deserialize(
        obj: PaillierCiphertext.SerializedPaillierCiphertext, **_kwargs: Any
    ) -> PaillierCiphertext:
        r"""
        Deserialization function for Paillier ciphertexts, which will be passed to the
        communication module.

        :param obj: serialized version of a PaillierCiphertext.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierCiphertext from the given dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        ciphertext = PaillierCiphertext(
            raw_value=obj["value"],
            scheme=obj["scheme"],
        )
        return ciphertext

    # endregion


class Paillier(
    AsymmetricEncryptionScheme[
        KeyMaterial,
        Plaintext,
        int,
        int,
        PaillierCiphertext,
        PaillierPublicKey,
        PaillierSecretKey,
    ],
    RandomizedEncryptionScheme[
        KeyMaterial, Plaintext, int, int, PaillierCiphertext, int
    ],
):
    """
    Paillier Encryption Scheme. This is an AsymmetricEncryptionScheme, with a public and secret key.
    This is also a RandomizedEncryptionScheme, thus having internal randomness generation and
    allowing for the use of precomputed randomness.
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
        RandomizedEncryptionScheme.__init__(
            self,
            debug=debug,
        )

        self.precision = precision
        self.max_value = FixedPoint(public_key.n // 2, precision=precision)
        self.min_value = -self.max_value

        # Variable that determines whether a secret key is sent when the scheme is sent
        # over a communication channel
        self.share_secret_key = share_secret_key

        self.client_history: list[HTTPClient] = []

    @staticmethod
    def generate_key_material(
        key_length: int,
    ) -> KeyMaterial:  # pylint: disable=arguments-differ
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
        new_ciphertext_fresh = ciphertext.fresh
        if new_ciphertext_fresh:
            warnings.warn(
                WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning, stacklevel=2
            )

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return PaillierCiphertext(
            mod_inv(ciphertext.get_value(), self.public_key.n_squared),
            self,
            fresh=new_ciphertext_fresh,
        )

    def add(
        self,
        ciphertext_1: PaillierCiphertext,
        ciphertext_2: PaillierCiphertext | Plaintext,
    ) -> PaillierCiphertext:
        r"""
        Secure addition.

        If ciphertext_2 is another PaillierCiphertext $c_2$, add the underlying plaintext value of
        ciphertext_1 $c_1$ with the underlying plaintext value of ciphertext_2. If it is a
        Plaintext, we add the plaintext value $m_2$ to ciphertext_1, by first encryption it and
        obtaining $c_2 = Enc(m_2)$. We then compute the result as $c' = c_1 \cdot c_2 \mod n^2$.

        The resulting ciphertext is fresh only if at least one of the inputs was fresh. Both inputs
        are marked as non-fresh after the operation.

        :param ciphertext_1: First PaillierCiphertext $c_1$ of which the underlying plaintext is
            added.
        :param ciphertext_2: Either a second PaillierCiphertext $c_2$ of which the underlying
            plaintext is added to the first. Or a plaintext $m_2$ that is added to the underlying
            plaintext of the first.
        :raise AttributeError: When ciphertext_2 does not have the same public key as ciphertext_1.
        :return: A PaillierCiphertext $c'$ containing the encryption of the addition of both values.
        """
        if isinstance(ciphertext_2, get_args(Plaintext)):
            ciphertext_2 = self.unsafe_encrypt(cast(Plaintext, ciphertext_2))
        elif ciphertext_1.scheme != cast(PaillierCiphertext, ciphertext_2).scheme:
            raise AttributeError(
                "The scheme of your first ciphertext is not equal to the scheme of your second "
                "ciphertext."
            )
        ciphertext_2 = cast(PaillierCiphertext, ciphertext_2)

        new_ciphertext_fresh = ciphertext_1.fresh or ciphertext_2.fresh
        if new_ciphertext_fresh:
            warnings.warn(
                WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning, stacklevel=2
            )

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return PaillierCiphertext(
            ciphertext_1.get_value()
            * ciphertext_2.get_value()
            % self.public_key.n_squared,
            self,
            fresh=new_ciphertext_fresh,
        )

    def mul(self, ciphertext: PaillierCiphertext, scalar: int) -> PaillierCiphertext:  # type: ignore[override]  # pylint: disable=arguments-renamed
        """
        Multiply the underlying plaintext value of ciph $c$ with the given scalar $s$.

        We obtain the result by computing $c' = c^s$.

        The resulting ciphertext is fresh only if the input was fresh. The input is marked as
        non-fresh after the operation.

        :param ciphertext: PaillierCiphertext $c$ of which the underlying plaintext is multiplied.
        :param scalar: A scalar $s$ with which the plaintext underlying ciph should be
            multiplied.
        :raise TypeError: When the scalar is not an integer.
        :return: PaillierCiphertext $c'$ containing the encryption of the product of both values.
        """
        # This check is necessary to support both built-in integers and gmpy2 integers
        # - The mpz class from gmpy2 is registered as a virtual subclass of numbers.Integral. Static type checkers
        #   do not understand such dynamic typing constructions, so the stubs define mpz as a subclass of int, but
        #   the runtime check is done on `numbers.Integral`.
        if not isinstance(scalar, numbers.Integral):
            raise TypeError(
                f"Type of  scalar (second multiplicand) should be an integer and not"
                f" {type(scalar)}."
            )
        if scalar < 0:
            ciphertext = self.neg(ciphertext)
            scalar = -scalar

        new_ciphertext_fresh = ciphertext.fresh
        if new_ciphertext_fresh:
            warnings.warn(
                WARN_INEFFICIENT_HOM_OPERATION, EncryptionSchemeWarning, stacklevel=2
            )

        # ciphertext.get_value() automatically marks ciphertext as not fresh
        return PaillierCiphertext(
            pow_mod(ciphertext.get_value(), scalar, self.public_key.n_squared),
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
        # Equality should still hold if the secret key is not available
        return (
            isinstance(other, Paillier)
            and self.precision == other.precision
            and self.public_key == other.public_key
        )

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
        return hash((public_key, precision))

    # region Serialization logic

    class SerializedPaillier(TypedDict, total=False):
        scheme_id: int
        prec: int
        pubkey: PaillierPublicKey
        seckey: PaillierSecretKey

    def serialize(
        self,
        *,
        destination: HTTPClient | list[HTTPClient] | None = None,
        **_kwargs: Any,
    ) -> Paillier.SerializedPaillier:
        r"""
        Serialization function for Paillier schemes, which will be passed to the communication
        module. The sharing of the secret key depends on the attribute share_secret_key.

        :param destination: HTTPClient representing where the message will go if applicable, can also be a list of
            clients in case of a broadcast message.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this Paillier scheme.
        """
        if isinstance(destination, HTTPClient):
            destination = [destination]
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if self.identifier not in self._instances:
            self.save_globally()
        if destination is not None and all(
            d in self.client_history for d in destination
        ):
            return {
                "scheme_id": self.identifier,
            }
        if destination is not None:
            for dest in destination:
                if dest not in self.client_history:
                    self.client_history.append(dest)
        if self.share_secret_key:
            return self.serialize_with_secret_key()
        return self.serialize_without_secret_key()

    def serialize_with_secret_key(
        self,
    ) -> Paillier.SerializedPaillier:
        """
        Serialization function for Paillier schemes, that does include the secret key.

        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this Paillier scheme.
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
        :return: serialized version of this Paillier scheme (without the secret key).
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
        *,
        origin: HTTPClient | None = None,
        **_kwargs: Any,
    ) -> Paillier:
        r"""
        Deserialization function for Paillier schemes, which will be passed to
        the communication module.

        :param obj: serialized version of a Paillier scheme.
        :param origin: HTTPClient representing where the message came from if applicable
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :raise ValueError: When a scheme is sent through ID without any prior communication of the
            scheme
        :return: Deserialized Paillier scheme from the given dict. Might not have a secret
            key when that was not included in the received serialization.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if "scheme_id" in obj:
            paillier: Paillier = Paillier.from_id(obj["scheme_id"])
            if origin is None:
                raise ValueError(
                    f"The scheme was sent through an ID, but the origin is {origin}"
                )
            if origin not in paillier.client_history:
                raise ValueError(
                    f"The scheme was sent through an ID by {origin.addr}:{origin.port}, "
                    f"but this scheme was never"
                    "communicated with this party"
                )
        else:
            pubkey = obj["pubkey"]
            precision = obj["prec"]
            # This piece of code is specifically used for the case where sending and receiving
            # happens between hosts running the same python instance (local network).
            # In this case, the Paillier scheme that was sent is already available before it
            # arrives and does not need to be created anymore.
            identifier = Paillier.id_from_arguments(
                public_key=pubkey, precision=precision
            )
            if identifier in Paillier._instances:
                paillier = Paillier.from_id(identifier)
            else:
                paillier = Paillier(
                    public_key=pubkey,
                    secret_key=obj["seckey"] if "seckey" in obj else None,
                    precision=precision,
                )
                paillier.save_globally()
        if origin is not None and origin not in paillier.client_history:
            paillier.client_history.append(origin)
        return paillier

    # endregion


if COMMUNICATION_INSTALLED:
    try:
        Serialization.register_class(Paillier)
        Serialization.register_class(PaillierCiphertext)
        Serialization.register_class(PaillierPublicKey)
        Serialization.register_class(PaillierSecretKey)
    except RepetitionError:
        pass
