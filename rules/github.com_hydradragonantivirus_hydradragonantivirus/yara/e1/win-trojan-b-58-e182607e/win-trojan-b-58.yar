rule Win_Trojan_B_58
{
strings:
	$a0 = { d3bc007c2e832e130403cd12c1e0068ec0b80602b90200ba8000cd130668 }


condition:
	$a0
}