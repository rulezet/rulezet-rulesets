rule Win_Trojan_Mayberry_11
{
strings:
	$a0 = { dc038d96df03cd21b440b9d902908d960601cd2132c0e828008d96db03cd21 }


condition:
	$a0
}