rule Win_Trojan_VGEN_570
{
strings:
	$a0 = { e800005d81ed33011e06eb0290e932e4cd1a81fa00fe7206e82e05eb0a9081fa00087703e84405b8 }


condition:
	$a0
}