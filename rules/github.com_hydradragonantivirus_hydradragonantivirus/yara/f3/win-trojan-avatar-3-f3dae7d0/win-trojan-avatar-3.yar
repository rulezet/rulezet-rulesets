rule Win_Trojan_Avatar_3
{
strings:
	$a0 = { f91f741fb802422bc999cd21b440b93902ba2701cd21b80057cd2183c91fb80157cd21b8014359 }


condition:
	$a0
}