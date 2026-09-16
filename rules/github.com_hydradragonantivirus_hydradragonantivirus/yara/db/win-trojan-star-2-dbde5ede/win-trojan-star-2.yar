rule Win_Trojan_Star_2
{
strings:
	$a0 = { c08ec0268b1e6c04891e660407b4 }


condition:
	$a0
}