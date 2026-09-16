rule Win_Trojan_Porno_1
{
strings:
	$a0 = { 7c90b811008ec08ed88b0ee601bfe801beeb01f3a4b90300bee801f3a4bada03ec240874fba0e301bac803ee428b0e }


condition:
	$a0
}