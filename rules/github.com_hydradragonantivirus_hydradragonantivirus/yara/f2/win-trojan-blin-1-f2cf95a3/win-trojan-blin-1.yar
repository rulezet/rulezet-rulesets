rule Win_Trojan_Blin_1
{
strings:
	$a0 = { 3c337411b8004233c999cd21fec6b1e6b440cd2147b801578bd559cd21b43ecd21b80143ba9e00 }


condition:
	$a0
}