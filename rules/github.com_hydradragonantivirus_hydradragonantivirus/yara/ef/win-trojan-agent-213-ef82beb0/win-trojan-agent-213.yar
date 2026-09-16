rule Win_Trojan_Agent_213
{
strings:
	$a0 = { fa33c08ed88ed068007c5c8b1e13044bbe4c00891e1304ada3407cada3427cc1e306c7064c00f800 }


condition:
	$a0
}