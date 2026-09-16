rule Win_Trojan_VGEN_168
{
strings:
	$a0 = { bb0000b90000cd21fc0e1f8cc82d08008ec0be8000bfb605b98000f3a4be000081c60001bf0001b9b604f3a406b8 }


condition:
	$a0
}