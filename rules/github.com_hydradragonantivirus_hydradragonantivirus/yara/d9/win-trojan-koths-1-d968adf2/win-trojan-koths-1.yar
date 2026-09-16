rule Win_Trojan_Koths_1
{
strings:
	$a0 = { d03869d1935acfc4d0e218e2031cf0a2d238f2d0659168d2d16b83d01cf0a2d238c5d03834d139fe }


condition:
	$a0
}