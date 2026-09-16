rule Win_Trojan_Monster_30
{
strings:
	$a0 = { 4bf26e6ff07648499c876b1cfe0d7898cb8c0548876b14a10cb40e55fe50f0c548499c876bca3655 }


condition:
	$a0
}