rule Win_Trojan_Split_3
{
strings:
	$a0 = { 0116090103fa5a061f47313c3114310c46e2f60e1fb440b91700ba0001cd21061f33d2b440b9 }


condition:
	$a0
}