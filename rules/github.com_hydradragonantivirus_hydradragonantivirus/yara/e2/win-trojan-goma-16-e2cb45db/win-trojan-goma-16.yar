rule Win_Trojan_Goma_16
{
strings:
	$a0 = { ccfc777183fa0e726c81ea33023b963703746281c23302899634038d963603cd21e8440032c0 }


condition:
	$a0
}