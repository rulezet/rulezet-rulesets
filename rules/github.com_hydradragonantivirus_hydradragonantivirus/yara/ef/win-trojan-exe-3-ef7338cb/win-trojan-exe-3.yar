rule Win_Trojan_Exe_3
{
strings:
	$a0 = { 02b91402b4408d160000cd21b8004233c933d2cd21b4408bd7b91800cd21b801572e8b0e }


condition:
	$a0
}