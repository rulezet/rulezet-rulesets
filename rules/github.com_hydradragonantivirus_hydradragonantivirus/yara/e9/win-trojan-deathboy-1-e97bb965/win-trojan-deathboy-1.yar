rule Win_Trojan_Deathboy_1
{
strings:
	$a0 = { 211e06b8000a500733ffb9b601568b944303ad2bc2abe2fa5e33d2061fb96d03b440cd2107 }


condition:
	$a0
}