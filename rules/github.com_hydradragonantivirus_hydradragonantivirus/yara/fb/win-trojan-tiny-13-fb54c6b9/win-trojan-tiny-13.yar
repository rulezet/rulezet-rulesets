rule Win_Trojan_Tiny_13
{
strings:
	$a0 = { 652abf9e0091b44e8bd6cd218bd7b82e5bae75fd66c705636f6d20cd21720793b440b129ebe2 }


condition:
	$a0
}