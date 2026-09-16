rule Win_Trojan_Small_5388
{
strings:
	$a0 = { 60e8000000005b80fcc66629db53e8 }


condition:
	$a0
}