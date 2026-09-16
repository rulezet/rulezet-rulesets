rule Win_Trojan_Lmir_132
{
strings:
	$a0 = { 85c00f843c06000068dca20014e8221100008bf08d44243050e81611000083c408 }


condition:
	$a0
}