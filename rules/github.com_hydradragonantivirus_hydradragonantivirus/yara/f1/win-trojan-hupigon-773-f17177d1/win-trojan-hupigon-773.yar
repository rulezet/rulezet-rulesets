rule Win_Trojan_Hupigon_773
{
strings:
	$a0 = { 8d85c0fcffff8d95f0feffffb904010000e8b78ff7ff8b85c0fcffffbab4c14800e84391f7ff751756bebcc148008dbdcdfcffffb97f000000f3a566a5a45e }


condition:
	$a0
}