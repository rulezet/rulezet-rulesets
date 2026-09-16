rule Win_Trojan_Pakes_982
{
strings:
	$a0 = { 4f7c33d252525251525703f8b85c6d6369abb871747a33abb8322e646cabb86c }


condition:
	$a0
}