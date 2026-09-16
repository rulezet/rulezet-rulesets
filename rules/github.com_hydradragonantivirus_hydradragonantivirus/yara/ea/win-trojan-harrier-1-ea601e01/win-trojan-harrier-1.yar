rule Win_Trojan_Harrier_1
{
strings:
	$a0 = { 617539fb6c48bcf81930e8e3bbb32949cac94668646c4353a12698069f27c0e945217f2d4c27b3f0 }


condition:
	$a0
}