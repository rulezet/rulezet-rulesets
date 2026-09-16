rule Win_Trojan_Game_2
{
strings:
	$a0 = { ffcd213d49e67450b82135cd2131c08ed82e891efa002e8c06fc00ff0e1304a11304b106d3e08ec031ffb920 }


condition:
	$a0
}