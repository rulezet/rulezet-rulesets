rule Win_Trojan_Mayak_2
{
strings:
	$a0 = { c08ed8c4060c002e89845e092e8c846009b8dafecd213defad7404c41e8400891e0c008c060e00 }


condition:
	$a0
}