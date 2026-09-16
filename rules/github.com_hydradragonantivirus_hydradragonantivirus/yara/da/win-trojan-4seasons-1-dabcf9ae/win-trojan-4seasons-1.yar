rule Win_Trojan_4Seasons_1
{
strings:
	$a0 = { 7767cd213d73867478e8de03a10f0680fc047510b400b3 }


condition:
	$a0
}