rule ElGamal_public_key_encryption__qbits___16_big_38_
{
strings:
	$a0 = { 0077009100a500b700c600d400e100ed00f90103010d0117012001280131013901400148014f }

condition:
	$a0
}