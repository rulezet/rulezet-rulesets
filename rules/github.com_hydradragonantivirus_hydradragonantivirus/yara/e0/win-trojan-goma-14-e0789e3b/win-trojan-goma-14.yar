rule Win_Trojan_Goma_14
{
strings:
	$a0 = { cd217226b8023dba9e00cd218bd8b98501ba0001b440cd21b43ecd21ebe043484b4c4953542e }


condition:
	$a0
}