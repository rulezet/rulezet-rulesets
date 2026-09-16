rule Win_Trojan_Flashfake_8
{
strings:
	$a0 = { 6e6465720047455400557365722d4167 }

	$a1 = { 7570646174653f69663d252666753d25 }


condition:
	$a0 and $a1
}