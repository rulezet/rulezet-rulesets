rule Win_Trojan_Virogen_11
{
strings:
	$a0 = { 34ae2ea86fae2ca88fb090f1ac28a2ad26ad28d6bbacaedb9edba7db68db83db7aafc7d6286624a9 }


condition:
	$a0
}