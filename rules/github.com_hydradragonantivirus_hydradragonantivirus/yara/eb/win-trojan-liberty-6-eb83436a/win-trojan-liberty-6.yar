rule Win_Trojan_Liberty_6
{
strings:
	$a0 = { cd0072c2bb13012e813f4d5a7505 }


condition:
	$a0
}