rule Win_Trojan_Arian_1
{
strings:
	$a0 = { 2a2e737973015cc8d603008cd38ec38cdbfc8dbe00ffc57606acaa9130edf3a48edbbf1f0a0e57 }


condition:
	$a0
}