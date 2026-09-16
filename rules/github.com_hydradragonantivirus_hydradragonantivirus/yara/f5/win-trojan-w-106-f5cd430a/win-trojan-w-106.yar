rule Win_Trojan_W_106
{
strings:
	$a0 = { 0a000033db5933db33d052585f525833d080372733d04733d0e2f233d061c3 }


condition:
	$a0
}