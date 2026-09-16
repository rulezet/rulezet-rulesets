rule Win_Trojan_KOV_4
{
strings:
	$a0 = { ba9b048bf2b96600e83401b002e82201a305058916070550a19b043d4d5a587420c606490400 }


condition:
	$a0
}