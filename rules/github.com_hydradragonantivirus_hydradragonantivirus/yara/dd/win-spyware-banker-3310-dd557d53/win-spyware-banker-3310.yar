rule Win_Spyware_Banker_3310
{
strings:
	$a0 = { 76b733f9a4e7bef6a1356a8b9f3eb11c48eadcef85d6fe73ad248739cf291c43462f52d75b8c3b30bfce34b656d4f5850dc95d7056a2fca48511b18e5a757a52ce50d0f78674 }


condition:
	$a0
}