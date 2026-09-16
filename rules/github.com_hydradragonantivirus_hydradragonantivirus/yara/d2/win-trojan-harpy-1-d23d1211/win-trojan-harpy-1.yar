rule Win_Trojan_Harpy_1
{
strings:
	$a0 = { 058bfe83ef10b970062eff74032e8a44032e3005 }


condition:
	$a0
}