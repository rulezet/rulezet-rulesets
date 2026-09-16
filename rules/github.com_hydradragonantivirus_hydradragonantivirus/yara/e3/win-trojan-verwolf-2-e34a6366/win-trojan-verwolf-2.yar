rule Win_Trojan_Verwolf_2
{
strings:
	$a0 = { c20963582caaf1b75a3e7bb8efcf63387d2765fba5d312025d2765b62db3c212630d3638652865b7 }


condition:
	$a0
}