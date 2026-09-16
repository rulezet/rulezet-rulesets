rule Win_Trojan_Staf_1
{
strings:
	$a0 = { ba7102cd21a15d02a35f02833e5f }


condition:
	$a0
}