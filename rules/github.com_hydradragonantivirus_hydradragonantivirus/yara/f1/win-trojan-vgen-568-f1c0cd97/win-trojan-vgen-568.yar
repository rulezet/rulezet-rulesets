rule Win_Trojan_VGEN_568
{
strings:
	$a0 = { 5d81ed30011e06eb01e932e4cd1a81fa00fe7205e8db05eb0981fa00087703e8f205b8f10b }


condition:
	$a0
}