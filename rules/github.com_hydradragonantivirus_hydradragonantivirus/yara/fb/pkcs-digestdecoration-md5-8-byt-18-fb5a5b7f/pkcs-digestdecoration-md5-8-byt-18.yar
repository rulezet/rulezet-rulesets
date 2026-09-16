rule PKCS_DigestDecoration_MD5__8_byt_18_
{
strings:
	$a0 = { 3020300c06082a864886f70d020505000410 }

condition:
	$a0
}