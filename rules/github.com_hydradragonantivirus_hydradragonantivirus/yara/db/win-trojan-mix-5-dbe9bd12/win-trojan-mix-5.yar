rule Win_Trojan_Mix_5
{
strings:
	$a0 = { e8000000005d83ed08db452ddb4531dee9db55358b4535b9c00100005531853807000083ed04e2f5eb21 }


condition:
	$a0
}