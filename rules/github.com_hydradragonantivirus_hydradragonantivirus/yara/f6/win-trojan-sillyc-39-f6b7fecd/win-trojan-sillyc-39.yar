rule Win_Trojan_SillyC_39
{
strings:
	$a0 = { 013b068c017417b800425133c933d2cd215981c18c00b4408d160001cd21b43ecd21b44febb9 }


condition:
	$a0
}