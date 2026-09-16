rule Win_Trojan_Spanska_2
{
strings:
	$a0 = { 8a96fe04b9b9038db640018bfe8a044632c2e8d4ffe2f6 }


condition:
	$a0
}