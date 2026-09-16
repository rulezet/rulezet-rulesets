rule Win_Trojan_OnlineGames_38
{
strings:
	$a0 = { 578bfb0334245f572b34245fe8b600000060e8b0000000e8ab000000e8000000005be8a000000053e89a }


condition:
	$a0
}