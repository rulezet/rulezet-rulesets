rule Win_Trojan_Grog_18
{
strings:
	$a0 = { cd2172b493b904008d960401b43fcd213e80be0401 }


condition:
	$a0
}