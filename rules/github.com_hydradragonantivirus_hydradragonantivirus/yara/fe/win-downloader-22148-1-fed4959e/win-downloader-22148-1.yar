rule Win_Downloader_22148_1
{
strings:
	$a0 = { 8d1d98203f0081c3eeef00008d1574f2400081c2fa23ffffffd203d88d839443ffff2d9443ffffffd08d1dfa65400081c3 }


condition:
	$a0
}