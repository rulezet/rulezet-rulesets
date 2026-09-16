rule Win_Trojan_Trivial_444
{
strings:
	$a0 = { 218bd8b97000ba0001b440cd21720ab43ecd21b44fcd21 }


condition:
	$a0
}