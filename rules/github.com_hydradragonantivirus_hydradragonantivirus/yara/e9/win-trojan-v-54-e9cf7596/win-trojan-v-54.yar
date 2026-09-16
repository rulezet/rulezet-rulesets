rule Win_Trojan_V_54
{
strings:
	$a0 = { 04008edec55408b413cd2f1e52cd2f58bff800ab58ab8edec544403d1701ab8cd8ab06577509d1e6b9ff01f3a67447b452cd2106bef80026c47f12268b5502 }


condition:
	$a0
}