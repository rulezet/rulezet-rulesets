rule Win_Trojan_No444_1
{
strings:
	$a0 = { 2e894501b440b90600cd2133c08ed8a06c040ac0eb0bb80103b90100ba8000cd13b43ecd21 }


condition:
	$a0
}