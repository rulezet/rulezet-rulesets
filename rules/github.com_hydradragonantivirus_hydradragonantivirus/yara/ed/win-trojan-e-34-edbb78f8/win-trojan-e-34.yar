rule Win_Trojan_E_34
{
strings:
	$a0 = { 35cd21ba7802b425cd218bd3bbf4028c4f048c4f088c }


condition:
	$a0
}