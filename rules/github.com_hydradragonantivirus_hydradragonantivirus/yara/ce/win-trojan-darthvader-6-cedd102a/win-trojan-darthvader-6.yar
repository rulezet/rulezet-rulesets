rule Win_Trojan_DarthVader_6
{
strings:
	$a0 = { 5784ed7447b82012cd2f268a1db81612 }


condition:
	$a0
}