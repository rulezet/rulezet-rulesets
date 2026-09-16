rule Win_Trojan_Gen_120
{
strings:
	$a0 = { 0700fcf3a4585b9db800015350cb9c }


condition:
	$a0
}