rule Win_Trojan_AntiMouse_1
{
strings:
	$a0 = { 01b43ecd2172a5b43cb90000ba0301cd217299a32501068b1e29015307b91e008b369101 }


condition:
	$a0
}