rule Win_Trojan_Trivial_453
{
strings:
	$a0 = { ba3b01cd21b42fcd21061f8d571eb8023dcd218bd8b80057cd215152b440b94200ba0001cd215a59 }


condition:
	$a0
}