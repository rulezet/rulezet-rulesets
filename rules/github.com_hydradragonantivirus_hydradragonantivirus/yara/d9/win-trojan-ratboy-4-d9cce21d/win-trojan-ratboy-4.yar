rule Win_Trojan_Ratboy_4
{
strings:
	$a0 = { 4eb90000ba2301cd21b8023dba9e00cd2193b440b93200 }


condition:
	$a0
}