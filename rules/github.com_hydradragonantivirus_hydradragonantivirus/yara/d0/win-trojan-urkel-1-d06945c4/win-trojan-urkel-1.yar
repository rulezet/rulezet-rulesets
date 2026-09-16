rule Win_Trojan_Urkel_1
{
strings:
	$a0 = { 8ec058b80102ba0000b90100cd13b840008ec026c60613007eb8809f8ec08edbbe4c00bf20 }


condition:
	$a0
}