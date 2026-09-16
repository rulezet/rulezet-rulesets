rule Win_Trojan_Goner_1
{
strings:
	$a0 = { c9466f726d42ff0bdd650d013370656e7461676f6e659f011ddcc501ba23c60e4974dcd96db6b10ea90130305ba811151bac097b28e3601fc95ec09edb80 }


condition:
	$a0
}