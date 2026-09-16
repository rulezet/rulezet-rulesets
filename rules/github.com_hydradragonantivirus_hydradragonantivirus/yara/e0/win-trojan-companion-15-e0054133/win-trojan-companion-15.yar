rule Win_Trojan_Companion_15
{
strings:
	$a0 = { 636fc645026db43cb90300baa201cd21720f93b440b92101ba0001cd21b43ecd21b44fcd2173 }


condition:
	$a0
}