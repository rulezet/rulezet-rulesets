rule Win_Trojan_Vole_6
{
strings:
	$a0 = { b440b9fb018d960600cd21e80500b43ecd21c38db63300b9a901803400464975f9c3 }


condition:
	$a0
}