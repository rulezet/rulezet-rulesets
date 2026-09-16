rule Win_Trojan_W_339
{
strings:
	$a0 = { 9a2786344b324bb0c3d861be7d928aa8b027f42821334bbc }


condition:
	$a0
}