rule Win_Trojan_Excess_1
{
strings:
	$a0 = { 3030bbcefacd213dcefa7503e9b40033c08ed88e0686008b1e84002e8c867b0e2e899e790e8e06 }


condition:
	$a0
}