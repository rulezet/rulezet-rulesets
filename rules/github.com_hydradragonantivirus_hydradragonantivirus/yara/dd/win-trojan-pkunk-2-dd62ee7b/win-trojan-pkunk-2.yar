rule Win_Trojan_Pkunk_2
{
strings:
	$a0 = { 6803b440b93206ba0001cd21b800422bc92bd2cd21b440 }


condition:
	$a0
}