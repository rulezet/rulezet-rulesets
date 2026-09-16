rule Win_Trojan_Popcorn_1
{
strings:
	$a0 = { e98945028bd5b440b92c01cd2172c431d231c9b80042cd218bd581c24901b80040b92000cd21 }


condition:
	$a0
}