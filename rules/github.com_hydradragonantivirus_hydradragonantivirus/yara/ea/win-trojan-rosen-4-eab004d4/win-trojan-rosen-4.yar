rule Win_Trojan_Rosen_4
{
strings:
	$a0 = { c80500108ec0be000133ffb98300f3a4bad400b41acd21 }


condition:
	$a0
}