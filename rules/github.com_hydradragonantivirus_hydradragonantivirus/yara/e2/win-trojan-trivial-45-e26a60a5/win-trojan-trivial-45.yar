rule Win_Trojan_Trivial_45
{
strings:
	$a0 = { 0500b001b43dcd2189c3ba0001b96900b440cd21b43ecd21ba0201b44fcd213c127428ba9e00bf }


condition:
	$a0
}