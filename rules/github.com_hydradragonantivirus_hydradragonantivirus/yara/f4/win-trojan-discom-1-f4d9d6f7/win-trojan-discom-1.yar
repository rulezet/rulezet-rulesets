rule Win_Trojan_Discom_1
{
strings:
	$a0 = { 8cc88ed88ec0b43fcd21498bfabe }


condition:
	$a0
}