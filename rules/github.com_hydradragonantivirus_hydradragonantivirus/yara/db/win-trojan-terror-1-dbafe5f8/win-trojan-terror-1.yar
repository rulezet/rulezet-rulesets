rule Win_Trojan_Terror_1
{
strings:
	$a0 = { 35cd212e891e27052e8c062905b821 }


condition:
	$a0
}