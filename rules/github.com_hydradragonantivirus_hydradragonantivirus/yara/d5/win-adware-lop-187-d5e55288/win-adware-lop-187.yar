rule Win_Adware_Lop_187
{
strings:
	$a0 = { 7bc8dc802d0ca9a0147ace4bff2cd4b0185f6d712012396788606e04b04b192d821663f9fc7bc4db70eedcd94d9f697b5b6ec7632150ef0ff9f21dd8 }


condition:
	$a0
}