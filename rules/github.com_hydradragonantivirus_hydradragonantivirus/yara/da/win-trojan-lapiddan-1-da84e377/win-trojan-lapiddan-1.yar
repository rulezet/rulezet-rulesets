rule Win_Trojan_Lapiddan_1
{
strings:
	$a0 = { 02008d96a202cd21b8024233c999cd21b440b912008d969802cd21b440b977028d961200cd }


condition:
	$a0
}