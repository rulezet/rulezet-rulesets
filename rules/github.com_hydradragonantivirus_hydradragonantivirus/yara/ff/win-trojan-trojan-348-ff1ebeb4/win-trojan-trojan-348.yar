rule Win_Trojan_Trojan_348
{
strings:
	$a0 = { e90000bb1301b900022e8137000083c302e2f6 }


condition:
	$a0
}