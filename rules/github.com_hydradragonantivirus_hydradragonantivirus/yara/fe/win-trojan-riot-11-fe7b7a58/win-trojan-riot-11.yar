rule Win_Trojan_Riot_11
{
strings:
	$a0 = { ffb91901ba4002b440cd21b8004233c999cd21b4408bd759cd215a59b80157cd21b43ecd2107 }


condition:
	$a0
}