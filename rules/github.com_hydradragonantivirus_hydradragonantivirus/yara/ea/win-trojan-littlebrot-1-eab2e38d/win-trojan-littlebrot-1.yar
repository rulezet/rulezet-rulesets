rule Win_Trojan_LittleBrot_1
{
strings:
	$a0 = { 44008ec0bf00018bf7b93301f3a48ed9be8400bf3302ba3501ad3bc27409 }


condition:
	$a0
}