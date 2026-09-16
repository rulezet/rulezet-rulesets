rule Win_Trojan_Syslock3551_1
{
strings:
	$a0 = { 8cd98ccf8edf8ec78ed78bfcbcdd0dfc }


condition:
	$a0
}