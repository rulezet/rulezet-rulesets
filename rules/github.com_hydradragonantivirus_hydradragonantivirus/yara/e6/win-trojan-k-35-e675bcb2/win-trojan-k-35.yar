rule Win_Trojan_K_35
{
strings:
	$a0 = { 0d012e8a8492032e8c84af0350061e0e0e071fffb48e03ffb49003ffb48a03ffb48c03ffb49303ffb495038d94f603 }


condition:
	$a0
}