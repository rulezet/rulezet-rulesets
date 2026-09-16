rule Win_Trojan_HFR_2
{
strings:
	$a0 = { cd218ad0fec2b447bee002cd21c3e8be00b43bb200bae002cd21b43bbae002cd21c3b409ba4603cd21bf2703c606 }


condition:
	$a0
}