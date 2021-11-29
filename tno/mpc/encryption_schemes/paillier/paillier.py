"""
Implementation of the Asymmetric Encryption Scheme known as Paillier.
"""

from __future__ import annotations

from queue import Queue
from secrets import randbelow
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from typing_extensions import get_args  # isort: split

from tno.mpc.encryption_schemes.templates.asymmetric_encryption_scheme import (
    AsymmetricEncryptionScheme,
    PublicKey,
    SecretKey,
)
from tno.mpc.encryption_schemes.templates.encryption_scheme import EncodedPlaintext
from tno.mpc.encryption_schemes.templates.randomized_encryption_scheme import (
    RandomizableCiphertext,
    RandomizedEncryptionScheme,
)
from tno.mpc.encryption_schemes.utils.fixed_point import FixedPoint
from tno.mpc.encryption_schemes.utils.utils import mod_inv, pow_mod, randprime

# Check to see if the communication module is available
try:
    from tno.mpc.communication.httphandlers import HTTPClient
    from tno.mpc.communication.serialization import Serialization

    COMMUNICATION_INSTALLED = True
except ModuleNotFoundError:
    COMMUNICATION_INSTALLED = False

fxp = FixedPoint.fxp


class SerializationError(Exception):
    """
    Serialization error for Paillier.
    """

    def __init__(self) -> None:
        super().__init__(
            "The tno.mpc.communication package has not been installed. "
            "Please install this package before you call the serialisation code."
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
        self.n_squared = n ** 2
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

    # region Serialization logic

    def serialize(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Serialization function for public keys, which will be passed to the communication module.

        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: JSON serialized version of this PaillierPublicKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "n": Serialization.serialize(self.n, **kwargs),
            "g": Serialization.serialize(self.g, **kwargs),
        }

    @staticmethod
    def deserialize(json_obj: Dict[str, Any], **kwargs: Any) -> PaillierPublicKey:
        """
        Deserialization function for public keys, which will be passed to the communication module.

        :param json_obj: JSON serialized version of a PaillierPublicKey.
        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierPublicKey from the given JSON dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return PaillierPublicKey(
            n=Serialization.deserialize(json_obj["n"], **kwargs),
            g=Serialization.deserialize(json_obj["g"], **kwargs),
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

    # region Serialization logic

    def serialize(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Serialization function for secret keys, which will be passed to the communication module.

        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: JSON serialized version of this PaillierSecretKey.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "lambda": Serialization.serialize(self.lambda_, **kwargs),
            "mu": Serialization.serialize(self.mu, **kwargs),
            "n": Serialization.serialize(self.n, **kwargs),
        }

    @staticmethod
    def deserialize(json_obj: Dict[str, Any], **kwargs: Any) -> PaillierSecretKey:
        """
        Deserialization function for public keys, which will be passed to the communication module

        :param json_obj: JSON serialized version of a PaillierSecretKey.
        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierSecretKey from the given JSON dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return PaillierSecretKey(
            lambda_value=Serialization.deserialize(json_obj["lambda"], **kwargs),
            mu=Serialization.deserialize(json_obj["mu"], **kwargs),
            n=Serialization.deserialize(json_obj["n"], **kwargs),
        )

    # endregion


KeyMaterial = Tuple[PaillierPublicKey, PaillierSecretKey]
Plaintext = Union[int, float, FixedPoint]


class PaillierCiphertext(RandomizableCiphertext[KeyMaterial, Plaintext, int, int]):
    """
    Ciphertext for the Paillier asymmetric encryption scheme. This ciphertext is rerandomizable
    and supports homomorphic operations.
    """

    scheme: Paillier  # type: ignore[assignment]

    def __init__(self: PaillierCiphertext, raw_value: int, scheme: Paillier):
        r"""
        Construct a RandomizableCiphertext, with the given value for the given EncryptionScheme.

        :param raw_value: PaillierCiphertext value $c \in \mathbb{Z}_{n^2}$.
        :param scheme: Paillier scheme that is used to encrypt this ciphertext.
        :raise TypeError: When the given scheme is not a Paillier scheme.
        """

        if not isinstance(scheme, Paillier):
            raise TypeError(f"expected Paillier scheme, got {type(scheme)}")
        super().__init__(raw_value, scheme)

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
        Create a copy of this Ciphertext, with the same value and scheme.

        :return: Copied PaillierCiphertext.
        """
        return PaillierCiphertext(raw_value=self._raw_value, scheme=self.scheme)

    # region Serialization logic

    def serialize(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Serialization function for Paillier ciphertexts, which will be passed to the communication
        module.

        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: JSON serialized version of this PaillierCiphertext.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "value": Serialization.serialize(self._raw_value, **kwargs),
            "scheme": Serialization.serialize(self.scheme, **kwargs),
        }

    @staticmethod
    def deserialize(json_obj: Dict[str, Any], **kwargs: Any) -> PaillierCiphertext:
        """
        Deserialization function for Paillier ciphertexts, which will be passed to the
        communication module.

        :param json_obj: JSON serialized version of a PaillierCiphertext.
        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PaillierCiphertext from the given JSON dict.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        raw_value = Serialization.deserialize(json_obj["value"], **kwargs)
        scheme = Serialization.deserialize(json_obj["scheme"], **kwargs)
        ciphertext = PaillierCiphertext(
            raw_value=raw_value,
            scheme=scheme,
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
    RandomizedEncryptionScheme[KeyMaterial, Plaintext, int, int, PaillierCiphertext],
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
        secret_key: Optional[PaillierSecretKey],
        precision: int = 0,
        share_secret_key: bool = False,
        randomizations: Optional[Queue[int]] = None,
        max_size: int = 100,
        total: Optional[int] = None,
        nr_of_threads: int = 1,
        path: Optional[str] = None,
        separator: str = ",",
        start_generation: bool = True,
        debug: bool = False,
    ):
        """
        Construct a new Paillier encryption scheme, with the given keypair, randomness object,
        precision for floating point encryption.

        :param public_key: Public key for this Paillier Scheme.
        :param secret_key: Optional Secret Key for this Paillier Scheme (None when unknown).
        :param precision: Floating point precision of this encoding (Default: 0), in decimal places.
        :param share_secret_key: Boolean value stating whether or not the secret key should be
            included in serialization. This should only be set to True if one is really sure of it.
            (Default: False)
        :param debug: flag to determine whether debug information should be displayed
            (Default: False)
        :param start_generation: flag that determines whether the scheme starts generating
            randomness immediately (Default: True)
        :param randomizations: queue with randomizations. If no queue is given, it creates a
            fresh one (Default: None)
        :param max_size: maximum size of the queue (Default: 100)
        :param total: upper bound on the total amount of randomizations to generate. (Default: None)
        :param nr_of_threads: number of generation worker threads that should be started
            (Default: 1)
        :param path: path (including filename) to the file that contains randomizations.
            By default no path is given and no randomness is extracted from any files. (Default: "")
        :param separator: separator for the random values in the given file (Default: ",")
        """
        AsymmetricEncryptionScheme.__init__(
            self, public_key=public_key, secret_key=secret_key
        )
        RandomizedEncryptionScheme.__init__(
            self,
            randomizations=randomizations,
            max_size=max_size,
            total=total,
            nr_of_threads=nr_of_threads,
            path=path,
            separator=separator,
            start_generation=start_generation,
            debug=debug,
        )

        self.precision = precision
        self.max_value = int(public_key.n // (2 * 10 ** precision))
        self.min_value = int(
            -(public_key.n - (public_key.n // 2 + 1)) // 10 ** precision
        )

        # Variable that determines whether a secret key is sent when the scheme is sent
        # over a communication channel
        self.share_secret_key = share_secret_key

        self.client_history: List[HTTPClient] = []

    @staticmethod
    def generate_key_material(key_length: int) -> KeyMaterial:  # type: ignore[override]  # pylint: disable=arguments-differ
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
                q = randprime(2 ** (key_length - 1), 2 ** key_length)
            n = p * q
        lambda_ = (p - 1) * (q - 1)
        g = n + 1
        mu = mod_inv(lambda_, n)  # use g = n + 1
        # mu = mod_inv(Paillier.func_l(pow(g, lambda_, n ** 2), n), n)  # use random g
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

    def _encrypt_raw(
        self,
        plaintext: EncodedPlaintext[int],
    ) -> PaillierCiphertext:
        r"""
        Encrypts an encoded (raw) plaintext value. Given a raw plaintext message
        $m \in \mathbb{Z}_n$, we select random $r \in \mathbb{Z}^*_n$ and compute the ciphertext
        value as $c = g^m \cdot r^n \mod n^2$

        :param plaintext: EncodedPlaintext object containing the raw value $m \in \mathbb{Z}_n$
            to be encrypted.
        :return: PaillierCiphertext object containing the encrypted plaintext $c$.
        """
        r = self.get_randomness()
        c = 1 + plaintext.value * self.public_key.n  # use g = n + 1
        c *= pow_mod(r, self.public_key.n, self.public_key.n_squared)
        c %= self.public_key.n_squared
        return PaillierCiphertext(c, self)

    def _decrypt_raw(self, ciphertext: PaillierCiphertext) -> EncodedPlaintext[int]:
        r"""
        Decrypts an ciphertext to its encoded plaintext value. Given a ciphertext
        $c \in \mathbb{Z}^*_{n^2}$, we compute the raw plaintext message as
        $m = L(c^\lambda \mod n^2) \cdot \mu \mod n.

        :param ciphertext: PaillierCiphertext object containing the ciphertext $c$ to be decrypted.
        :return: EncodedPlaintext object containing the encoded decryption $m$ of the ciphertext.
        """
        c = ciphertext.value
        c_lambda = pow_mod(c, self.secret_key.lambda_, self.public_key.n_squared)
        m = Paillier.func_l(c_lambda, self.secret_key.n)
        m *= self.secret_key.mu
        m %= self.secret_key.n
        return EncodedPlaintext(m, self)

    def neg(self, ciphertext: PaillierCiphertext) -> PaillierCiphertext:
        r"""
        Negate the underlying plaintext of this ciphertext. I.e. if the original plaintext of
        this ciphertext was 5. this method returns the ciphertext that has -5
        as underlying plaintext. Given a ciphertext $c$ we compute the negated ciphertext $c'$
        such that $c \cdot c' = 1 \mod n^2$

        :param ciphertext: PaillierCiphertext $c$ of which the underlying plaintext should be
            negated.
        :return: PaillierCiphertext $c'$ corresponding to the negated plaintext.
        """
        return PaillierCiphertext(
            mod_inv(ciphertext.value, self.public_key.n_squared), self
        )

    def add(
        self,
        ciphertext_1: PaillierCiphertext,
        ciphertext_2: Union[PaillierCiphertext, Plaintext],
    ) -> PaillierCiphertext:
        r"""
        Add the underlying plaintext value of ciphertext_1 $c_1$ with the underlying plaintext
        value of ciphertext_2 if ciphertext_2 is another PaillierCiphertext $c_2$, if it is a
        Plaintext, we add the plaintext value $m_2$ to ciphertext_1, by first encryption it and
        obtaining $c_2 = Enc(m_2)$.

        We then compute the result as $c' = c_1 \cdot c_2 \mod n^2$

        :param ciphertext_1: First PaillierCiphertext $c_1$ of which the underlying plaintext is
            added.
        :param ciphertext_2: Either a second PaillierCiphertext $c_2$ of which the underlying
            plaintext is added to the first. Or a plaintext $m_2$ that is added to the underlying
            plaintext of the first.
        :raise AttributeError: When ciphertext_2 does not have the same public key as ciphertext_1.
        :return: A PaillierCiphertext $c'$ containing the encryption of the addition of both values.
        """
        if isinstance(ciphertext_2, get_args(Plaintext)):
            ciphertext_2 = self.encrypt(cast(Plaintext, ciphertext_2))
        elif (
            ciphertext_1.scheme.public_key
            != cast(PaillierCiphertext, ciphertext_2).scheme.public_key
        ):
            raise AttributeError(
                "The public key of your first ciphertext is not equal to the "
                "public key of your second ciphertext."
            )
        return PaillierCiphertext(
            ciphertext_1.value
            * cast(PaillierCiphertext, ciphertext_2).value
            % self.public_key.n_squared,
            self,
        )

    def mul(self, ciphertext: PaillierCiphertext, scalar: int) -> PaillierCiphertext:  # type: ignore[override]
        """
        Multiply the underlying plaintext value of ciph $c$ with the given scalar $s$.
        We obtain the result by computing $c' = c^s$.

        :param ciphertext: PaillierCiphertext $c$ of which the underlying plaintext is multiplied.
        :param scalar: A scalar $s$ with which the plaintext underlying ciph should be
            multiplied.
        :raise TypeError: When the scalar is not an integer.
        :return: A PaillierCiphertext $c'$ containing the encryption of the product of both values.
        """
        if not isinstance(scalar, int):
            raise TypeError(
                f"Type of  scalar (second multiplicand) should be an integer and not"
                f" {type(scalar)}."
            )
        if scalar < 0:
            ciphertext = self.neg(ciphertext)
            scalar = -scalar
        return PaillierCiphertext(
            pow(ciphertext.value, scalar, self.public_key.n_squared), self
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

    def generate_randomness(self) -> int:
        r"""
        Method to generate randomness value $r^n \mod n^2$, from a random number
        $r \in_R \mathbb{Z}^*_{n}$ for Paillier.

        :return: A random number.
        """
        random_element = randbelow(self.public_key.n - 1) + 1
        modulus = self.public_key.n_squared
        n = self.public_key.n
        return pow_mod(random_element, n, modulus)

    def random_plaintext(self) -> FixedPoint:
        """
        Generate a uniformly random plaintext

        :return: A uniformly random element from the plaintext space represented as a fixed point
                 number.
        """
        min_val_fxp = fxp(self.min_value, target_precision=self.precision)
        max_val_fxp = fxp(self.max_value, target_precision=self.precision)
        return FixedPoint.random_range(min_val_fxp, max_val_fxp)

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
    def id_from_arguments(  # type: ignore[override]
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

    def serialize(
        self, *, destination: Optional[HTTPClient] = None, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Serialization function for Paillier schemes, which will be passed to the communication
        module. The sharing of the secret key depends on the attribute share_secret_key.

        :param kwargs: optional extra keyword arguments
        :param destination: HTTPClient representing where the message will go if applicable
        :raise SerializationError: When communication library is not installed.
        :return: JSON serialized version of this Paillier scheme.
        """

        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if self.identifier not in self._instances:
            self.save_globally()
        if destination in self.client_history:
            return {
                "scheme_id": Serialization.serialize(self.identifier),
            }
        if destination is not None and destination not in self.client_history:
            self.client_history.append(destination)
        if self.share_secret_key:
            return self.serialize_with_secret_key(**kwargs)
        return self.serialize_without_secret_key(**kwargs)

    def serialize_with_secret_key(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Serialization function for Paillier schemes, that does include the secret key.

        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: JSON serialized version of this Paillier scheme.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "prec": Serialization.serialize(self.precision, **kwargs),
            "pubkey": Serialization.serialize(self.public_key, **kwargs),
            "seckey": Serialization.serialize(self.secret_key, **kwargs),
        }

    def serialize_without_secret_key(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Serialization function for Paillier schemes, that does not include the secret key.

        :param kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: JSON serialized version of this Paillier scheme (without the secret key).
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        return {
            "prec": Serialization.serialize(self.precision, **kwargs),
            "pubkey": Serialization.serialize(self.public_key, **kwargs),
        }

    @staticmethod
    def deserialize(
        json_obj: Dict[str, Any], *, origin: Optional[HTTPClient] = None, **_kwargs: Any
    ) -> Paillier:
        """
        Deserialization function for Paillier schemes, which will be passed to
        the communication module.

        :param json_obj: JSON serialized version of a Paillier scheme.
        :param _kwargs: optional extra keyword arguments
        :param origin: HTTPClient representing where the message came from if applicable
        :raise SerializationError: When communication library is not installed.
        :raise ValueError: When a scheme is sent through ID without any prior communication of the
            scheme
        :return: Deserialized Paillier scheme from the given JSON dict. Might not have a secret
            key when that was not included in the received serialization.
        """
        if not COMMUNICATION_INSTALLED:
            raise SerializationError()
        if "scheme_id" in json_obj:
            identifier = Serialization.deserialize(json_obj["scheme_id"])
            paillier: Paillier = Paillier.from_id(identifier)
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
            pubkey = Serialization.deserialize(json_obj["pubkey"])
            precision = Serialization.deserialize(json_obj["prec"])
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
                    secret_key=Serialization.deserialize(json_obj["seckey"])
                    if "seckey" in json_obj
                    else None,
                    precision=precision,
                    nr_of_threads=0,
                    start_generation=False,
                )
                paillier.save_globally()
        if origin is not None and origin not in paillier.client_history:
            paillier.client_history.append(origin)
        return paillier

    # endregion


if (
    COMMUNICATION_INSTALLED
    and "Paillier" not in Serialization.new_deserialization_funcs
):
    Serialization.set_serialization_logic(Paillier)
    Serialization.set_serialization_logic(PaillierCiphertext)
    Serialization.set_serialization_logic(PaillierPublicKey)
    Serialization.set_serialization_logic(PaillierSecretKey)
