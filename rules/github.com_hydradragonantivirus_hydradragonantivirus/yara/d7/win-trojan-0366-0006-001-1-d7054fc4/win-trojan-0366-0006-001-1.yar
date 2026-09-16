rule Win_Trojan__0366_0006_001_1
{
strings:
	$a0 = { d2b80042cd21b920008d96db03b440cd21720d8b8e13048b961504b80157cd21b43ecd218d }


condition:
	$a0
}