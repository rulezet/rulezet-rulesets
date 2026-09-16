rule Win_Trojan_DrJohn_1
{
strings:
	$a0 = { 072e2b0e50022ec606280100b440cd210e07b8004233c92e8b163001cd21b440ba5806b90a00 }


condition:
	$a0
}