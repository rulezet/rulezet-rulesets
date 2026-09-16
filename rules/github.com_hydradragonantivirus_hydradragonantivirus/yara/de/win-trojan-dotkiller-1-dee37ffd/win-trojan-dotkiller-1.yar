rule Win_Trojan_DotKiller_1
{
strings:
	$a0 = { 01b440cd21e8bf02b440b90300baa704cd21b801 }


condition:
	$a0
}