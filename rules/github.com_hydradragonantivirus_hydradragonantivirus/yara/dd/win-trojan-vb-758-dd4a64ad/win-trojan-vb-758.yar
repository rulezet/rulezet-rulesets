rule Win_Trojan_VB_758
{
strings:
	$a0 = { 9c60e8000000005d83ed078d9da0feffff8a033c0074108d9dc8feffff8a033c010f8442020000c603018bd52b955c }


condition:
	$a0
}