rule Win_Trojan_Necrfear_1
{
strings:
	$a0 = { 5533ed1e06530e0e1f07e8b5ff5b071fb8024233c933d2cd21b440b91f07900e1f33d2cd21 }


condition:
	$a0
}