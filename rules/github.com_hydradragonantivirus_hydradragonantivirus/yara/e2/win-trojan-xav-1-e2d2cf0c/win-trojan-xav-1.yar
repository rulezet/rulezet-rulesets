rule Win_Trojan_Xav_1
{
strings:
	$a0 = { 8b2f83c40281ed????b90b018db65c018bfe56ad33865a01abe2f8c3 }


condition:
	$a0
}