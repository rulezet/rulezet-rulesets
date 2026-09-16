rule Win_Trojan_Dejmi_1
{
strings:
	$a0 = { 213c06751380fa0e750eb403b001b280b600b500b101cd13be5b038e065903bb5703bf0001 }


condition:
	$a0
}