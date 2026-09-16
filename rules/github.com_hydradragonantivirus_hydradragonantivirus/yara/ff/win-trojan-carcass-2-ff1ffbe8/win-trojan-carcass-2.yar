rule Win_Trojan_Carcass_2
{
strings:
	$a0 = { fa77043bf07211b80125c5160507e844ffe888ff806617fe1f61cf596f75722070756c76657269 }


condition:
	$a0
}