rule Win_Trojan_SillyC_74
{
strings:
	$a0 = { 860001b802428b9eac0133c933d2cd21b440b9b5008d96ff00cd218b8600012d03008986b201b8 }


condition:
	$a0
}