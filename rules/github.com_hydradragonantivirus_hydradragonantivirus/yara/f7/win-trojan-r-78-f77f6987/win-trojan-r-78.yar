rule Win_Trojan_R_78
{
strings:
	$a0 = { 0333dbcd16c3e81400eb25e80f00b440b99c018bd5cd21e80300c300008db63f00b9af002e8b562a2e31144646e2 }


condition:
	$a0
}