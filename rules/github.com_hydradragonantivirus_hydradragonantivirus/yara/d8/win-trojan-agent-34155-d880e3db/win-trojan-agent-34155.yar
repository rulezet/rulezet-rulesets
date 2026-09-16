rule Win_Trojan_Agent_34155
{
strings:
	$a0 = { 57f7df5f6081c73150bf5381ef3150bf }


condition:
	$a0
}