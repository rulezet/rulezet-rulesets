rule Win_Trojan_Ciadoor_2
{
strings:
	$a0 = { f3f12009ca0500466fc1ffffcb726d0d011d00432e492e41202076312e3231202d20210fee4b7020230f001963b72201 }


condition:
	$a0
}