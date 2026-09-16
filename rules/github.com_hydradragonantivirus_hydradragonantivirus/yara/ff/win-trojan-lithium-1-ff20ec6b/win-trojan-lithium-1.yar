rule Win_Trojan_Lithium_1
{
strings:
	$a0 = { c2cb78df01e3d2421545d2d4ce40cad6ced378df01e37e4c24accabec92465cabf32ff05470d4714 }


condition:
	$a0
}