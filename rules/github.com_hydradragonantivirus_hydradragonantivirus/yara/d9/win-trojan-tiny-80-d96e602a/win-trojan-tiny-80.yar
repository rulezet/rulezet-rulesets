rule Win_Trojan_Tiny_80
{
strings:
	$a0 = { ba7ffdcd2152a1ee0050fec4a37f018bf9b8004233d233c9cd21 }


condition:
	$a0
}