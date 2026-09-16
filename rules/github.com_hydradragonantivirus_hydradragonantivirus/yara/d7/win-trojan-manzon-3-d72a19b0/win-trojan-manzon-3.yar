rule Win_Trojan_Manzon_3
{
strings:
	$a0 = { a28106b87406ffd0be0001b98605b83307ffd046e2f88b1ee706b440b98605ba00019c0e }


condition:
	$a0
}