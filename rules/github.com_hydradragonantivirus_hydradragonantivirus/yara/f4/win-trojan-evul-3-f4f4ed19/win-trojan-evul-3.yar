rule Win_Trojan_Evul_3
{
strings:
	$a0 = { 04008d96ca00cd21fe86ce00b802422bc999cd21b440b932018d960600cd21b43ecd21c3 }


condition:
	$a0
}