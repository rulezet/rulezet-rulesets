rule Win_Trojan_Mind_1
{
strings:
	$a0 = { b9de07ba00012bca2e8b1ef5049c2eff1e9d030f92c23bc80f95c65233d2e8cefbe84cfb2e8b1e }


condition:
	$a0
}