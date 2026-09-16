rule Win_Trojan_4_1
{
strings:
	$a0 = { 1e068bf00592008bd88cc88ed8bf00018b47fc89058a }


condition:
	$a0
}