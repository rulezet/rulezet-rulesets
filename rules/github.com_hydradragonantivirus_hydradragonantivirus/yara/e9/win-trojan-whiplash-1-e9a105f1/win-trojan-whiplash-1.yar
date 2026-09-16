rule Win_Trojan_Whiplash_1
{
strings:
	$a0 = { f8c3f9c3b440b9e711ba3713e83ef9c3fa601e060e1fb82435cd218c06a801891eaa01b824 }


condition:
	$a0
}