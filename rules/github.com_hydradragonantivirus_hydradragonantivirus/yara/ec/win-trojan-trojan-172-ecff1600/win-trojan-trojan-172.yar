rule Win_Trojan_Trojan_172
{
strings:
	$a0 = { ba2401cd21721ab8023dba9e00cd21b740b12aba000193cd21b43ecd21b44febdfc3 }


condition:
	$a0
}