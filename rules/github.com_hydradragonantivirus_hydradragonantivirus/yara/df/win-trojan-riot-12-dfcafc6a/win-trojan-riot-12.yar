rule Win_Trojan_Riot_12
{
strings:
	$a0 = { 1e0633c08ed88ec0bf4002397d2574198d76fdb919012ef3a4bf5904be840056a5a55fb81304ab91ab071f0be47b00 }


condition:
	$a0
}