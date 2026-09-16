rule TEA_encryption_decryption__0xc6ef3720__0x9e3779b9___32_lil_AND_
{
strings:
	$a0 = { 2037efc6[0-20]b979379e }

condition:
	$a0
}