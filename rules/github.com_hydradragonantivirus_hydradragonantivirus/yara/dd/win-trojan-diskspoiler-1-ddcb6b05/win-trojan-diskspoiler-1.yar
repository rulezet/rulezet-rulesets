rule Win_Trojan_Diskspoiler_1
{
strings:
	$a0 = { 5e8bfeb90b0580750eff9047e2f8 }


condition:
	$a0
}