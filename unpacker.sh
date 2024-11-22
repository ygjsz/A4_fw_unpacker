#!/bin/sh

exec 2>&1
set -eu


package=$1
OUTDIR=$2

if [ ! -d $OUTDIR ]; then
  mkdir $OUTDIR;
fi
if [ ! -d $OUTDIR ]; then  # check again
  echo "! Err: looks like we cannot create this folder"
  exit 0
fi

echo $OUTDIR
rm -rf "$OUTDIR/*"
contents_sign_key="./key.pub"
device_dec_key="./key.private"
preparation_sign="$OUTDIR/preparation_archive.sig"
preparation_archive="$OUTDIR/preparation_archive.zip"
contents_sign="$OUTDIR/contents_sign.sig"
contents_key="$OUTDIR/contents_key.key"
contents_iv="$OUTDIR/contents_iv.iv"
contents_archive="$OUTDIR/contents_archive.zip"
contents=$package.contents

echo_int32 ()
{
  hexdump -s$2 -n$3 -e '/4 "%u "' $1
}

extract_file ()
{
  tail -c+$(($2 + 1)) $1 | head -c$3
}

hexdump_fixed ()
{
  hexdump -ve '/1 "%02x"' $2 | egrep "^[0-9a-f]{$1}$"
}

echo "###Check $package..."
header_size=20
set -- $(echo_int32 $package 0 $header_size)
[ "$1" -eq $((0x50555044)) ]  # "DPUP" (little endian)
contents_offset=$2
contents_size=$3
echo "###Done!"

echo "###Extract files: preparation..."
# preparation: sign/archive
preparation_offset=$((contents_offset + contents_size))
preparation_header_size=12
set -- $(echo_int32 $package $preparation_offset $preparation_header_size)
preparation_sign_offset=$((preparation_offset + preparation_header_size))
preparation_archive_offset=$((preparation_sign_offset + $3))
extract_file $package $preparation_sign_offset $3 > $preparation_sign
extract_file $package $preparation_archive_offset $2 > $preparation_archive
echo "###Done!"

echo "###Verify signature: preparation..."
openssl dgst -sha256 \
  -verify $contents_sign_key \
  -signature $preparation_sign < $preparation_archive
echo "###Done!"

echo "###Extract files..."
set -- $(echo_int32 $package 0 $header_size)
# sign/contents
extract_file $package $header_size $5 > $contents_sign
extract_file $package $contents_offset $contents_size > $contents
contents_key_size_offset=$((header_size + $5))
contents_key_size=$(echo_int32 $package $contents_key_size_offset 4)
contents_key_offset=$((contents_key_size_offset + 4))
extract_file $package $contents_key_offset $contents_key_size > $contents_key
# init vector
contents_iv_offset=$((contents_key_offset + contents_key_size))
extract_file $package $contents_iv_offset 16 > $contents_iv
echo "###Done!"

echo "###Verify signature..."
openssl dgst -sha256 \
  -verify $contents_sign_key \
  -signature $contents_sign < $contents

echo "###Decrypt contents..."
contents_dec_key=$(mktemp)
openssl rsautl -decrypt \
  -inkey $device_dec_key \
  -in $contents_key -out $contents_dec_key
openssl enc -d -aes-256-cbc \
  -K  "$(hexdump_fixed 64 $contents_dec_key)" \
  -iv "$(hexdump_fixed 32 $contents_iv)" \
  -in $contents -out $contents_archive
rm -f $contents
echo "###Done!"

echo "###All Done!"


