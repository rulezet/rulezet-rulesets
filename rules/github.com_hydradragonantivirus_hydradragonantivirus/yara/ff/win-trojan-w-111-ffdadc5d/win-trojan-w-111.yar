rule Win_Trojan_W_111
{
strings:
	$a0 = { c07504b8b34acf3d05167405ea000000009c2eff1e2d00 }


condition:
	$a0
}