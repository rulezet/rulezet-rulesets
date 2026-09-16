rule Win_Trojan_AVCS_4
{
strings:
	$a0 = { 5b81eb12018beb8db63301568b962d02b97a008bfe84fffcad33c2ab84d8e2f8c3 }


condition:
	$a0
}