rule Win_Trojan_Kamasya_1
{
strings:
	$a0 = { d7c3b440b94a04ba0001e80a00eb01 }


condition:
	$a0
}