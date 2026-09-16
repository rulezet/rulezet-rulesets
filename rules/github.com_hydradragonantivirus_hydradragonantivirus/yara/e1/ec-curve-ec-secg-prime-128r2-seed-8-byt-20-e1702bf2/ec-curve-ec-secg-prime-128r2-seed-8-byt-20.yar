rule EC_curve__EC_SECG_PRIME_128R2_SEED__8_byt_20_
{
strings:
	$a0 = { 004d696e67687561517512d8f03431fce63b88f4 }

condition:
	$a0
}