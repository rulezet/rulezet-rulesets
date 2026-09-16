rule Win_Trojan_Mini_71
{
strings:
	$a0 = { ba4e0133c9cd217242ba9e00b8023dcd218bd8b43fb154b2a051cd21722d }


condition:
	$a0
}