rule Win_Trojan_VGEN_106
{
strings:
	$a0 = { 83ee03bf0001fc8cc81e8ed88ec0684001bbf000c707f2a4c7470261c3b9640e60ffe30a57414e44455245522c2863 }


condition:
	$a0
}