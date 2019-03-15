# This script creates a directory with a private/public keypair, which could be used from Java
# For this reason check: http://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
# The keys are created in a defined directory ($DIRECTORY)
# If the directory already contains a keypair the keypair is not! replaced

DIRECTORY="clientKeys"
PRIV_KEY="private_key"
PUB_KEY="public_key"

# create keys directory if it does not exist
if [ ! -d $DIRECTORY ]; then
	mkdir $DIRECTORY
fi

if [ ! -e  $DIRECTORY/$PRIV_KEY.pem ]; then
# generate a 2048-bit RSA private key
openssl genrsa -out $DIRECTORY/$PRIV_KEY.pem 2048
fi

if [ ! -e  $DIRECTORY/$PRIV_KEY.der ]; then
# convert private Key to PKCS#8 format (so Java can read it)
openssl pkcs8 -topk8 -inform PEM -outform DER -in $DIRECTORY/$PRIV_KEY.pem -out $DIRECTORY/$PRIV_KEY.der -nocrypt
fi

if [ ! -e  $DIRECTORY/$PUB_KEY.der ]; then
# output public key portion in DER format (so Java can read it)
openssl rsa -in $DIRECTORY/$PRIV_KEY.pem -pubout -outform DER -out $DIRECTORY/$PUB_KEY.der
fi
