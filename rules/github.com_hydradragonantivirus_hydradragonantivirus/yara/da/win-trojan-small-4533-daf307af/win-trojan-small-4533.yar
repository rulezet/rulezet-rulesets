rule Win_Trojan_Small_4533
{
strings:
	$a0 = { bdf9??400055b9????40008b09ffd101d5e84400000089e9 }


condition:
	$a0
}