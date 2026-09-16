rule Win_Trojan_Prospero_1
{
strings:
	$a0 = { 01ba0000cd17be7801b9bd01b400accd17e2f9b8004ccd2150726f737065726f20566972757328 }


condition:
	$a0
}