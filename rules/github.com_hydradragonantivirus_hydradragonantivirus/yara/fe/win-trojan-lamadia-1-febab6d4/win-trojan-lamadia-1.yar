rule Win_Trojan_Lamadia_1
{
strings:
	$a0 = { ff2574304000ff2570304000 }


condition:
	$a0
}