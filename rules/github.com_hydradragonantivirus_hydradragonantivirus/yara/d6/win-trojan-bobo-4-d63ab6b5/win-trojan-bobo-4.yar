rule Win_Trojan_Bobo_4
{
strings:
	$a0 = { 5d83ed2bbf0001be180001eea4a4a4b8bb4bcd213d4bbb74dcb82135cd212e899e91002e8c8693000e58485007 }


condition:
	$a0
}