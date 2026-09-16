rule Win_Trojan_Ammy_1
{
strings:
	$a0 = { eae18de78bc3ede1fef78be782cdfbfcfcebe0fac8e7e2ebaa9ce788cfc1feebe0aa9ce782ddfaeffcfafbfec8e7e2ebaa9cfceae18ae788cfcbf6ebedaa88eae18de92d0ee28f8eeae18c9493eae18ce783c3f7d1c2 }


condition:
	$a0
}