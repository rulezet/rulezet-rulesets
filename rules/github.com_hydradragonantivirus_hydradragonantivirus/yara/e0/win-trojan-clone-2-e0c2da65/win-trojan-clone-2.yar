rule Win_Trojan_Clone_2
{
strings:
	$a0 = { 9e00cd2193b44050b93000ba0001cd2158b99300bacd01cd21b43ecd21b44f50ebaab409 }


condition:
	$a0
}