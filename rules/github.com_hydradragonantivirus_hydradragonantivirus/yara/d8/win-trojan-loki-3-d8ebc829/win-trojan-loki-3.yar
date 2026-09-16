rule Win_Trojan_Loki_3
{
strings:
	$a0 = { b9cb03ba0001e8380033c933d2b800422e8b1e8404e82900ba7904b440b90500e81e00e82200 }


condition:
	$a0
}