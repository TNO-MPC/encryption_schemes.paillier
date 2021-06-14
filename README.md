# TNO MPC Lab - Encryption Schemes - Paillier

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package tno.mpc.encryption_schemes.paillier is part of the TNO Python Toolbox.

Implementation of the Paillier encryption scheme with support with precomputation of randomness. The encryption scheme supports positive and negative numbers, as well as fixed point encoding of numbers. Homomorphic addition of ciphertexts, negation of ciphertexts, and multiplication of ciphertexts with integral scalars has been included too.

*Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws.*

## Documentation

Documentation of the tno.mpc.encryption_schemes.paillier package can be found [here](https://docs.mpc.tno.nl/encryption_schemes/paillier/1.0.3).

## Install

Easily install the tno.mpc.encryption_schemes.paillier package using pip:
```console
$ python -m pip install tno.mpc.encryption_schemes.paillier
```

### Note:
A significant performance improvement can be achieved by installing the GMPY2 library.
```console
$ python -m pip install 'tno.mpc.encryption_schemes.paillier[gmpy]'
```

If you wish to use the tno.mpc.communication module you can use:
```console
$ python -m pip install 'tno.mpc.encryption_schemes.paillier[communication]'
```

If you wish to run the tests you can use:
```console
$ python -m pip install 'tno.mpc.encryption_schemes.paillier[tests]'
```

## Usage

```python
from tno.mpc.encryption_schemes.paillier import Paillier

if __name__ == "__main__":
    # initialize Paillier with key_length of 2048 bits and fixed point precision of 3 decimals
    paillier_scheme = Paillier.from_security_parameter(key_length=2048, precision=3)
    # encrypt the number 8.1
    ciphertext_1 = paillier_scheme.encrypt(8.1)
    # add 0.9 to the original plaintext
    ciphertext_1 += 0.9
    # multiply the original plaintext by 10
    ciphertext_1 *= 10
    # encrypt the number 10
    ciphertext_2 = paillier_scheme.encrypt(10)
    # add both encrypted numbers together
    encrypted_sum = ciphertext_1 + ciphertext_2
    # decrypt the encrypted sum to 100
    decrypted_sum = paillier_scheme.decrypt(encrypted_sum)
    assert decrypted_sum == 100
```
