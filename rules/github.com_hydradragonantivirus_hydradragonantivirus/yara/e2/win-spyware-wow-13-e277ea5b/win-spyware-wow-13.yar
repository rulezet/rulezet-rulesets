rule Win_Spyware_WOW_13
{
strings:
	$a0 = { 68ec3e400064ff3064892068f83e40006a006801001f00e8d8f7ffff85c0752268083f40006a006801001f00e8c3f7ffff85c0750d8d45ece85bfaffffe8fafdffff }


condition:
	$a0
}