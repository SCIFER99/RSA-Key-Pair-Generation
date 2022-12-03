# By: Tim Tarver also known as CryptoKeyPlayer

# This script was designed to generate an RSA public and private
# key pair for encrypting any web application.

# import cryptosyspki as pki
# import Gen

import os
import sys
import pytest
import shutil
from glob import iglob
import tempfile
import requests
import crypto

# We now begin the function to generate our RSA Key Pairs
# for securing the web application (or website) using the
# fastest algorithm possible (until updates say otherwise).
# 512-bit encryption for speed is not secure so we will use
# 1024-bit instead.

def rsa_keypair_generator():

    print("\n TEST RSA KEY FUNCTIONS....")
    print(" MAking a new 512-bit RSA Key Pair...")
    rsa_private_key_file = "myrsaprivate.p8"
    rsa_public_key_file = "myrsapublic.p1"
    rsa_key_generator = pki.RSA.make_keys(rsa_public_key_file, rsa_private_key_file,
                                          1024, pki.RSA.PublicExponent.RSAEXP_EQ_65537,
                                          'password')
    assert (rsa_key_generator == 0)

    # The lines below reads from the key pair file into and puts it into an
    # internal private key string. Now print out the private and public key pair

    private_key_string = pki.RSA.read_private_key(rsa_private_key_file, 'password')
    print("Private Key String = ", private_key_string)
    assert (len(private_key_string) > 0)
    number_of_bits = pki.RSA.key_bits(private_key_string)
    print("Number of Private Bits = ", number_of_bits)
    assert (number_of_bits > 0)
    print("HashCode = ", pki.RSA.key_hashcode(private_key_string))

    public_key_string = pki.RSA.read_public_key(rsa_public_key_file)
    print("Public Key String = ", public_key_string)
    assert (len(public_key_string) > 0)
    number_of_bits2 = pki.RSA.key_bits(public_key_string)
    print("Number of Public Bits = ", number_of_bits2)
    assert (number_of_bits2 > 0)
    print("HashCode = ", pki.RSA.key_hashcode(public_key_string))

    # Prepare the Exponent and Modulus values to be used in Encryption.

    exponent = pki.RSA.key_value(public_key_string, "Exponent")
    print("Exponent in Base64: ", exponent)

    modulus = pki.RSA.key_value(public_key_string, "Modulus")
    print("Modulus in Base64: ", modulus)

    # The lines below create an XML file version of the Public Key
    # String and converts them into non-standard Base 64
    # hexadecimal values and standard Base64 values.

    non_standard_hex = pki.RSA.from_xmlstring(public_key_string,
                                              pki.RSA.XmlOptions.HEXBINARY)
    print("Hexadecimal Version of XML: ", non_standard_hex)

    standard_hex = pki.RSA.to_xmlstring(public_key_string)
    print("Standard XML Value: ", standard_hex)

    # The lines below goes back to our XML String to a new
    # internal string different from the first one with same hash code.

    new_internal_string = pki.RSA.from_xmlstring(standard_hex)
    print("New Key String: ", new_internal_string)
        
    print("HashCode = ", pki.RSA.keu_hashcode(new_internal_string))

    


# The docstring below consists of print statements to be ran
# by the test functions itself separate from the RSA Key Pair
# Generator function.

"""
# This line is the minimum PKI version constant

min_pki_version_constant = 200300

# First, we want to display information about the main PKI Crypto system

print("PKI Version = ", pki.Gen.version())
print("Module Name = ", pki.Gen.module_name())
print("Compile Time = ", pki.gen.compile_time())
print("Platform = ", pki.Gen.core_platform())
print("License Type = ", pki.Gen.license_type())
print("Module Info = ", pki.Gen.module_info())

# Secondly, we must display some values of the system we might need.

print("sys.getdefaultencoding() = ", sys.getdefaultcoding())
print("sys.getfilesystemencoding() = ", sys.getfilesystemencoding())
print("sys.platform() = ", sys.platform)
print("cwd = ", os.getcwd())

# Make the system require a current version or higher (if not previously installed)

if pki.Gen.version() < min_pki_version_constant:
    raise Exception('Require PKI Version' + str(min_pki_version_constant) + 'or greater')

# We define our global variables to create and initialize a temporary directory
# used for security tests.

initial_directory = os.getcwd()
current_temporary_directory = ""

# This line will be used to depete our directory when we do not need it
# anymore.

delete_temporary_directory = True

# We begin defining our function that sets up our temporary directory
# and use it to put our test files in it.

"""

# The methods below is the process to create a temporary directory
# to transfer files you want to store and encrypt.

"""

def setup_temporary_directory():

    global current_temporary_directory
    
    # This is the sub-directory to the current temporary directory
    # and we change from initial temporary directory to working directory.
    
    working_directory = os.path.join(initial_directory, "work")
    print("\n Expecting to find work directory: ", woring_directory)
    assert os.path.isdir(working_directory)

    # Insert all test files needed to create a temporary sub-directory
    # in the work directory.

    current_temporary_directory = os.path.join(working_directory, "pki.tmp." +
                                               pki.Cnv.tohex(pki.Rng.bytestring(4)))
    os.mkdir(current_temporary_directory)

    assert os.path.isdir(current_temporary_directory)

    # Now, copy all temporary files

    for files in iglob(os.path.join(working_directory, "*.*")):
        if os.path.isfile(files) and not files.endswith('.zip'):
            shutil.copy(files, current_temporary_directory)

    # Change the currenct working directory to be inside temporary directory.

    os.chdir(current_temporary_directory)
    print("Working in new temporary directory: ", os.getcwd())

"""    

# The next method is designed to reset the starting directory and
# removes the temporary directory.

"""

def reset_initial_directory():

    if not os.path.isdir(initial_directory):
        return
    if (current_temporary_directory == initial_directory):
        return
    os.chdir(initial_directory)
    print("")

    # Then print the current working directory (cwd) and remove the temporary
    # directory.

    if (delete_temporary_directory and 'pki.tmp' in current_temporary_directory):
        print("Removing Temporary Directory: ", current_temporary_directory)
        shutil.rmtree(current_temporary_directory, ignore_errors = True)

"""

# The methods below utilize the Pytest module to begin setting up our security tests
# with decorators that call fixtures and receive data we want to test.


"""
@pytest.fixture(scope = "module", autouse = True)
def divider_module(request):

    print("\n --- module %s() start ---" % request.module.__name__)
    setup_temp_dir()

    def finalize_module():

        print("\n --- module %s() done ---" % request.function.__name__)
        reset_initial_directory()
        request.addfinalizer(finalize_module)

@pytest.fixture(scope = "function", autouse = True)
def divider_function(request):

    print("\n --- function %s() start ---" % request.function.__name__)
    os.chdir(current_temporary_directory)

    def finalize_function():
        print("\n --- function %s() done ---" % request.function.__name__)
        os.chdir(initial_directory)
        request.addfinalizer(finalize_function)
"""


# The methods below begin implementing CRUD Operations via functions to print, read,
# write, update and delete which ever binary or text files necessary.

"""

def read_binary_file(filename):

    with open(filename, "rb") as file1:
        return bytearray(file1.read())

def write_binary_file(filename, data):

    with open(filename, "wb") as file1:
        file1.write(data)

def read_text_file(filename, enc = 'utf8'):

    with open(filename, encoding = enc) as file1:
        return file1.read()

def write_text_file(filename, save, enc = 'utf8'):

    with open(filename, "w", encoding = enc) as file1:
        file1.write(save)

def print_file(filename):

    text_file = read_text_file(filename)
    print(text_file)

def print_hexdecimal_file(filename):

    binary_file = read_binary_file(filename)
    print(pki.Cnv.tohex(binary_file)

def file_dumper(filename):

    string_1 = read_text_file(filename)
    n_dash = (24 if len(string_1) > 24 else len(string_1))
    print("FILE: ", filename)
    print("-" * n_dash)
    print(string_1)
    print("-" * n_dash)

def x509_printer_and_dumper(filename):

    dumpfile = 'temporarydump.txt'
    if os.path.isfile(filename):
        print("FILE: ", filename)
    else:
         print("STRING: ", filename)

    try:
       pki.X509.text_dump(dumpfile, filename)
       print_file(dumpfile)
    except pki.PKIError as e:
       print("Whoops! PKI Error: ", e)

def asn1_printer_and_dumper(filename, opts = 0):

    if os.path.isfile(filename):
       print("FILE: ", filename)
    else:
        print("STRING: ", filename)

    (filedump, dumpfile) = tempfile.mkstemp()
    try:
       pki.Asn1.text_dump(dumpfile, filename, opts)
       string = read_text_file(dumpfile)
       print(string)
       os.close(filedump)
    except pki.PKIError as e:
        print("Whoops! PKIError: ", e)
    finally:
        os.remove(dumpfile)

"""


    
    

    
    
    
