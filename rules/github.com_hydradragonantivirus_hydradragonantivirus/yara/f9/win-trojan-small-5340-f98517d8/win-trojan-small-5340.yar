rule Win_Trojan_Small_5340
{
strings:
	$a0 = { 947943ef6b0d2ae1231c756d695563ee63508e2ce2d44ad392e8ce8ade04b7474bb5154470bbaf452c8fb17330f98943dfc1dbdc724c11f8b222b27941fe637a43 }


condition:
	$a0
}