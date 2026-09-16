rule Win_Trojan_AntiAVP_1
{
strings:
	$a0 = { 894515b440b9d304ba0000cd21b43ecd215826884504eb }


condition:
	$a0
}