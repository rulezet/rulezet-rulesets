rule Win_Trojan_VGEN_210
{
strings:
	$a0 = { cd2180fa15740ab409ba2b02cd21eb1290b409babf01cd21b9e803b8070ecd10e2fce91e019c80fc4b7402eb39b8 }


condition:
	$a0
}