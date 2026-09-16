rule Win_Trojan_Proxy_121
{
strings:
	$a0 = { 807c2408010f85b901000060be007000108dbe00a0ffff57eb109090909090908a06 }

	$a1 = { 6e307a2e646c6c00696c6972 }


condition:
	$a0 and $a1
}