rule Win_Trojan_Perflog_52
{
strings:
	$a0 = { e95f100000000000009090906a006858 }

	$a1 = { 000062706b2e657865 }


condition:
	$a0 and $a1
}