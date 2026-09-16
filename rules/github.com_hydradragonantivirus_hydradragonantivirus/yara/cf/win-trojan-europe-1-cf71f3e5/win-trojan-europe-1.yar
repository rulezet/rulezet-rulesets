rule Win_Trojan_Europe_1
{
strings:
	$a0 = { cd218cd8488ed8c60600005a891e }


condition:
	$a0
}