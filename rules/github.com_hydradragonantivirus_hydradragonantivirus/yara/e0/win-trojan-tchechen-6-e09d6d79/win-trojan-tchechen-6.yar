rule Win_Trojan_Tchechen_6
{
strings:
	$a0 = { 7408807c040074f1ebcdb40ebe9d06b9e800accd10e2fbfaf420496e76616c6964207061727469 }


condition:
	$a0
}