rule Win_Trojan_Small_4444
{
strings:
	$a0 = { 83ec04b89fcfbdfff7d089e28902ba22 }


condition:
	$a0
}