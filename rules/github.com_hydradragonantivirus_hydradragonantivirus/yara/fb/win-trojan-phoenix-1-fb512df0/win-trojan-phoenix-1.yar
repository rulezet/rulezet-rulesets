rule Win_Trojan_Phoenix_1
{
strings:
	$a0 = { 90e8000087c05e95b8d603508bde33c92e334c1f46464879f75a2e31 }


condition:
	$a0
}