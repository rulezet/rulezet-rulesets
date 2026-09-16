rule Win_Trojan_VrapExe_2
{
strings:
	$a0 = { c08ed8be0400bfa904fca5a5c744fcb1048c44febe0c00bfad04fca5a5c744fcb2048c44fe }


condition:
	$a0
}