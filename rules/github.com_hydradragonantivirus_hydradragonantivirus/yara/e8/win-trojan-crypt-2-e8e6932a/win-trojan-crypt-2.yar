rule Win_Trojan_Crypt_2
{
strings:
	$a0 = { bf18018a97180183fb6e90740980ea198ac243aaebed }


condition:
	$a0
}