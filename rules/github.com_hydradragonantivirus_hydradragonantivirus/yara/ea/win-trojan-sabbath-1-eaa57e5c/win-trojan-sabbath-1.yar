rule Win_Trojan_Sabbath_1
{
strings:
	$a0 = { e90000bb1201b943038137????83c302e2f7 }


condition:
	$a0
}