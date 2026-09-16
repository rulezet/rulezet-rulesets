rule Win_Trojan_DKiller_2
{
strings:
	$a0 = { 04008d962803cc3e81be280390e97503eb4290b802 }


condition:
	$a0
}