rule Win_Trojan_MemoryLapse_3
{
strings:
	$a0 = { 2bc999cc5250b440b96e018d960001ccb8024233c999ccb90002f7f1403e89865102 }


condition:
	$a0
}