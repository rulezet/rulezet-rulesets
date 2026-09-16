rule Win_Trojan_Vole_7
{
strings:
	$a0 = { b440b9ff018d960600cd21e80500b43ecd21c38db63300b9ad01803400464975f9c3 }


condition:
	$a0
}