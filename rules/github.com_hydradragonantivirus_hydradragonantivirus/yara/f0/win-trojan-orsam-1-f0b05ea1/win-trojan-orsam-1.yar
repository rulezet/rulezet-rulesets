rule Win_Trojan_Orsam_1
{
strings:
	$a0 = { 130403cd12c1e0068ec0b80602b90200ba8000cd130668d409cb2e891e4d0a2e891e730a8e }


condition:
	$a0
}