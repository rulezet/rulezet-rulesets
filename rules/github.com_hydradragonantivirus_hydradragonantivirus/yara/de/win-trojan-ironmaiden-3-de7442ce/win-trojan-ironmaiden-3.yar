rule Win_Trojan_IronMaiden_3
{
strings:
	$a0 = { 868d02b440b97b038d960001cd21b8004233c933d2cd21b8ff3fba0300428bca8d968c0240cd21 }


condition:
	$a0
}