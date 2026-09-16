rule Win_Trojan_Goma_4
{
strings:
	$a0 = { b9e7038d960601cd21c3595aebbfb44233c999cd218bd0b440b90300c3b440c35b54444727 }


condition:
	$a0
}