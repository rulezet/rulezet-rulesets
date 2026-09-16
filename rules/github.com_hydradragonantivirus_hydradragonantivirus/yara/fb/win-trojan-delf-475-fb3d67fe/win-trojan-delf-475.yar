rule Win_Trojan_Delf_475
{
strings:
	$a0 = { e81486ffffa3144a41006affa1f849410050e88a87ffff833d144a410000740e8bc3bab4c64000e8d571ffffeb0c }


condition:
	$a0
}