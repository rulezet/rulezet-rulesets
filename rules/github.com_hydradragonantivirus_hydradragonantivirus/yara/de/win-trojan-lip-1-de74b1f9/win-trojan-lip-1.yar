rule Win_Trojan_Lip_1
{
strings:
	$a0 = { 461501740733c9b80143cd21b8023dcd2172248bd8b43f }


condition:
	$a0
}