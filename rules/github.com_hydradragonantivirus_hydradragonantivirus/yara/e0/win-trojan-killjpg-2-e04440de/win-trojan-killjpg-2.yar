rule Win_Trojan_Killjpg_2
{
strings:
	$a0 = { e800005d81ed0801b91a018db6????8bfe8ab6????ac32c6aae2faeb01 }


condition:
	$a0
}