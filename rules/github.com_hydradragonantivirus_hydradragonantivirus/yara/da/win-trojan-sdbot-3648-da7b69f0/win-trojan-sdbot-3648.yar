rule Win_Trojan_SdBot_3648
{
strings:
	$a0 = { 23fc7d669d1520053dc07e9cefead9cbb16328e7de5b3e14488fe51a0a51b4b070cbb46bd3ccee530729013a3bcb4e7ba9532012465b0e4fbc28ed028672ad2add3701c5694f0b06ae7f971cb7bd }


condition:
	$a0
}