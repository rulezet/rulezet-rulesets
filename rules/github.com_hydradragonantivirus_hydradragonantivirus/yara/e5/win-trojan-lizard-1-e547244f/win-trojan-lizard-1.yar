rule Win_Trojan_Lizard_1
{
strings:
	$a0 = { 40b901008d96bc01cd2159e2f1b440b952008d965105cd21b440b931018d960001cd21b9e30951 }


condition:
	$a0
}