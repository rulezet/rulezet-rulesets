rule Win_Trojan_Dream_5
{
strings:
	$a0 = { 685effffff68ffd061e9685f586a026824c607006853448b3c68ff5360ff }


condition:
	$a0
}