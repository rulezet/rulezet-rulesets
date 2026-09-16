rule Win_Trojan_Baby_1
{
strings:
	$a0 = { cd21891e64018c066601ba1801b425cd21b299cd2780fc4b75465653515706501e52bf68015789d60e07acaa0a }


condition:
	$a0
}