rule Win_Trojan_Trivial_327
{
strings:
	$a0 = { 1801b425cd21b271cd2780fc4b751e60061eb43cb100cd210e1f93b440b93c00ba0001cd21b43e }


condition:
	$a0
}