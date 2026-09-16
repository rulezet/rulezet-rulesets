rule Win_Trojan_SillyC_1
{
strings:
	$a0 = { fec4a3bb01b440b9c300ba0001cd218f06bb01b8024233c999cd21b440b9c300ba0602cd21 }


condition:
	$a0
}