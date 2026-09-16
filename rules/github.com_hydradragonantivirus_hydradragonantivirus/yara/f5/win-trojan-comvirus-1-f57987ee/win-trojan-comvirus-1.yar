rule Win_Trojan_Comvirus_1
{
strings:
	$a0 = { fbfafab8004233c98bd1cd21b440b905008d56f8cd21 }


condition:
	$a0
}