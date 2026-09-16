rule Win_Trojan_Kahla_1
{
strings:
	$a0 = { baa601b82125cd21ea480111008cd08ed88ec08b3684 }


condition:
	$a0
}