rule Win_Trojan_AntiMD_1
{
strings:
	$a0 = { ff8edf8ed7be007c8bde8be6fbff0e1304cd12b90602d3e08ec0b825000650f3a4cb60b404cd1a }


condition:
	$a0
}