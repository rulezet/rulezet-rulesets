rule Win_Trojan_Small_154
{
strings:
	$a0 = { f2ae741eb002e8270050b440b19acd21e81b008bfab0e9aa5840abb05aaab440cd21b43ecd21 }


condition:
	$a0
}