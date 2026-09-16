rule Win_Trojan_FakeVirX_1
{
strings:
	$a0 = { 8bd5b90600cd21b801575a59cd21b4 }


condition:
	$a0
}