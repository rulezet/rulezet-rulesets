rule Win_Trojan_Dialer_698
{
strings:
	$a0 = { 4a0ec8806c0e400cc865656c3771709db9b281ff70000e5ad7fe0d4e303038382c3231 }

	$a1 = { 3a2f2f66cb2e74726166 }


condition:
	$a0 and $a1
}