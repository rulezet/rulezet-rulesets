rule Win_Trojan_Resvir90_1
{
strings:
	$a0 = { 8b2e010181c5030133c033dbb909 }


condition:
	$a0
}