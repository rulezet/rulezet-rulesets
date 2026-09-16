rule Win_Trojan_SillyC_101
{
strings:
	$a0 = { 93018f068e01be00018bfeb9d200fcf3a4736f061e078d36d201bf0001b99c77f3a51fb41aba }


condition:
	$a0
}