rule Win_Trojan_VGEN_642
{
strings:
	$a0 = { cd217347b44abbffffcd21b44a83eb10cd21b448bb0f00cd212d10008ec026c706f1000800bf03018bec8b7600 }


condition:
	$a0
}