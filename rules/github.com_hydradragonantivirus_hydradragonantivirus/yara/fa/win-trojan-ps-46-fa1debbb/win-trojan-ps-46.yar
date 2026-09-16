rule Win_Trojan_PS_46
{
strings:
	$a0 = { be97142e81045d1c4646e2f78be4a33bd0f5a36e8b02a99bf1247005e02cf757090f7e98ed2e700526cff997edb0c455f966d1e5 }


condition:
	$a0
}