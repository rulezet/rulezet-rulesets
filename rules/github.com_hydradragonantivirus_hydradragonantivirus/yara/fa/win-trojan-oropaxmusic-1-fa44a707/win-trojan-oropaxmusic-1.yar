rule Win_Trojan_OropaxMusic_1
{
strings:
	$a0 = { b8e033cd213cff7423bcce8ec68b36 }


condition:
	$a0
}