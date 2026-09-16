rule Win_Trojan_LittleBrother_3
{
strings:
	$a0 = { 501e063d004b7503e80b00071f585b5a9d2eff2e41 }


condition:
	$a0
}