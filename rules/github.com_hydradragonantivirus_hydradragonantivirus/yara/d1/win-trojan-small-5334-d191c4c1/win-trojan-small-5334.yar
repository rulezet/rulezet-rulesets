rule Win_Trojan_Small_5334
{
strings:
	$a0 = { 231c756d695563ee63508e2ce2d44ad392e8ce8ade04b7474bb5154470bbaf452c8fb17330f98943dfc1dbdc724c11f8b222b27941fe637a432b9b239cb9b6ac06 }


condition:
	$a0
}