rule Win_Trojan_Reboot_4
{
strings:
	$a0 = { 5c4175746f53657475705c5265626f6f74 }

	$a1 = { 546f6f6c735c44656c466f6c646572732e657865 }

	$a2 = { 5c52756e4f6e6365 }


condition:
	$a0 and $a1 and $a2
}