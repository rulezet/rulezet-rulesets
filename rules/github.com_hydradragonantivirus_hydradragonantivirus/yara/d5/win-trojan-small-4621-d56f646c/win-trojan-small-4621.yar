rule Win_Trojan_Small_4621
{
strings:
	$a0 = { 31ed81c5cb?c0cf881c535653408558d9de8f2afff81c334125000bf01?84?0089e151ff17b8ffdf11b12945008d6d0439dd7ee7c3 }


condition:
	$a0
}