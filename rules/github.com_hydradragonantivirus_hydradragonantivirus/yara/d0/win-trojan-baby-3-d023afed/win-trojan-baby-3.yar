rule Win_Trojan_Baby_3
{
strings:
	$a0 = { 268865fe5fcd21b43cb102cd210e1f93b440ba0001cd }


condition:
	$a0
}