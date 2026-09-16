rule Win_Trojan_SdBot_3675
{
strings:
	$a0 = { 877d81cec2ad76159d269b2cfe81963a8cdecc5fde90e7e8589cb010e2521c5a2d8cf03135da5a85de9d6cfc7cafac2a2ae9653eb7b569767e0de67f6c17867402e120e17c9f0a3de62d39f3b1bd }


condition:
	$a0
}