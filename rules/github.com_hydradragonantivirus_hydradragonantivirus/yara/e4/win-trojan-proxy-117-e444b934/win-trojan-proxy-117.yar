rule Win_Trojan_Proxy_117
{
strings:
	$a0 = { e81609843de91608bd6ecccccccc518d4c24042bc8 }

	$a1 = { 696f6e5c52756e[0-3]50726f6d6f526567 }


condition:
	$a0 and $a1
}