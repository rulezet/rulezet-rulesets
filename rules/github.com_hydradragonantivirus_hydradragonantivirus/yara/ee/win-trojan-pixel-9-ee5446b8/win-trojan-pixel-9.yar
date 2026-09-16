rule Win_Trojan_Pixel_9
{
strings:
	$a0 = { 8cc80500108ed8b41aba18f9cd21b44e1eb1200e1fba8301cd211fba36f97241b8023dcd21723133d2b43fb9ffff }


condition:
	$a0
}