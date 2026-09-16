rule Win_Trojan_Tool_2
{
strings:
	$a0 = { 09cd21b9fa00e800005d81ed130151ba9a0133c9b8023ccd2193b440b9ff00baba01cd21eb00b43ecd21bf }


condition:
	$a0
}