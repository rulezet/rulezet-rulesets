rule PKCS_DigestDecoration_MD2__8_byt_18_
{
strings:
	$a0 = { 3020300c06082a864886f70d020205000410 }

condition:
	$a0
}