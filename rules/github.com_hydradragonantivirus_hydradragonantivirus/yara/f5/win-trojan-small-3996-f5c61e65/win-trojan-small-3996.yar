rule Win_Trojan_Small_3996
{
strings:
	$a0 = { 31ed81c5cb0c0cf881c535653408558d9de8f2afff81c3341250 }


condition:
	$a0
}