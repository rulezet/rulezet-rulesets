rule Win_Trojan_ADI_2
{
strings:
	$a0 = { ba9e00b43cb92000cd2193720eb440ba0001b91d06cd21b43ecd21b44fcd2173d9c32a2e436f }


condition:
	$a0
}