rule Win_Trojan_BNB_2
{
strings:
	$a0 = { cd13a1bc033d5068741abfbc03b8540003c6505eb91700f3a4ba8000b80103b90100cd135f }


condition:
	$a0
}