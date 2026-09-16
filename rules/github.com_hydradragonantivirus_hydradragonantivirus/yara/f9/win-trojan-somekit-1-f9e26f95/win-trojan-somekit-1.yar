rule Win_Trojan_SomeKit_1
{
strings:
	$a0 = { 20005059ba01fab8455992cd169292b9a001bb26002e8107000083c30283e90175f3 }


condition:
	$a0
}