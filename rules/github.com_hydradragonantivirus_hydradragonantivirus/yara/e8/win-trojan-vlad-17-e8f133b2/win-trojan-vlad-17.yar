rule Win_Trojan_VLAD_17
{
strings:
	$a0 = { e65bdbf63f40e5563997700c3de02287d5ee4eaaf0dfe5017b754a0cc609d22fbd15431ba0dced85e829a95b0a51a837 }


condition:
	$a0
}