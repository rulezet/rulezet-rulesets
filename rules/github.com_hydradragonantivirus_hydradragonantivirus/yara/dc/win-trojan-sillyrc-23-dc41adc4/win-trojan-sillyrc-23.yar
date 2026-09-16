rule Win_Trojan_SillyRC_23
{
strings:
	$a0 = { cd213c937450b82135cd21891e18028c061a020e58488ed833ff8a1dc6054d8b55038b450183ea3103c28955038e }


condition:
	$a0
}