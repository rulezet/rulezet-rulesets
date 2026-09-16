rule Win_Trojan_SomeKit_3
{
strings:
	$a0 = { 20005059ba01fab8455992cd1692929292929292b9aa01bb2b002e8107000083c30283e90175f3 }


condition:
	$a0
}