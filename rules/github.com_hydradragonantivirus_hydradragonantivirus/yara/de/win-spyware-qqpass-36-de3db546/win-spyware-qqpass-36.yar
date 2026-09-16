rule Win_Spyware_QQPass_36
{
strings:
	$a0 = { e891ecffff50e817f2ffff68004f40006a006801001f00e8bef2ffff85c0751568104f40006a006801001f00e8a9f2ffff85c0740a }


condition:
	$a0
}