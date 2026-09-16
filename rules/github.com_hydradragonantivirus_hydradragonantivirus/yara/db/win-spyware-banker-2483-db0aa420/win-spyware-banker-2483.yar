rule Win_Spyware_Banker_2483
{
strings:
	$a0 = { a1f01c0acdd5e5b345b7a164adb2831a432e146c16c93d37a25ac5161670c5de5ff2a8a5dd9b6fb3a4780130f37e52cccc670e42db3a76d7f7858e457ffd65bfd8b3efa75328fd0b6300 }


condition:
	$a0
}