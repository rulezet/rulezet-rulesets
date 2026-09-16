rule Win_Trojan_Small_4414
{
strings:
	$a0 = { 56575355e8c7000000e981000000ffcb }


condition:
	$a0
}