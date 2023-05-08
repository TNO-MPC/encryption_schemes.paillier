"""
Implementation of the Paillier cryptosystem.
"""

# Explicit re-export of all functionalities, such that they can be imported properly. Following
# https://www.python.org/dev/peps/pep-0484/#stub-files and
# https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    EncryptionSchemeWarning as EncryptionSchemeWarning,
)

from tno.mpc.encryption_schemes.paillier.paillier import Paillier as Paillier
from tno.mpc.encryption_schemes.paillier.paillier import (
    PaillierCiphertext as PaillierCiphertext,
)
from tno.mpc.encryption_schemes.paillier.paillier import (
    PaillierPublicKey as PaillierPublicKey,
)
from tno.mpc.encryption_schemes.paillier.paillier import (
    PaillierSecretKey as PaillierSecretKey,
)

__version__ = "3.0.1"
