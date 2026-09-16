rule Win_Trojan_Crepate_2
{
strings:
	$a0 = { fbb80300362906132533ac1609b106d3e08ec02e8b4c692e8b546bfec1b8050233dbcd1373 }


condition:
	$a0
}