rule Win_Trojan_BigMouse_4
{
strings:
	$a0 = { 5a0e1fb8ff2583c21190cd21cdffeb1390b9e0018bf283c61290813493194646e2f8cf }


condition:
	$a0
}