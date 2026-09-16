rule Win_Trojan_DIR_1
{
strings:
	$a0 = { ff77fe26c51f8b40153d7000751091c64018ff8b7813c7 }


condition:
	$a0
}