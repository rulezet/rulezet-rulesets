rule Win_Trojan_Golgi_3
{
strings:
	$a0 = { c745020100b440b98101ba0001cd2126c74515000026c745170000b440b90300ba8102cd21 }


condition:
	$a0
}