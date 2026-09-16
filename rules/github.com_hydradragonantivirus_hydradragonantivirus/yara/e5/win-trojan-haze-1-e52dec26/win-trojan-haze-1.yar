rule Win_Trojan_Haze_1
{
strings:
	$a0 = { 2acaf1a9e032be0317a8135426dd24d8e3a1f620ac1f092c8816100236cdbd3a79d0a1c111bc037c }


condition:
	$a0
}