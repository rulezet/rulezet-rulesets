rule Win_Trojan_Tranquilo_2
{
strings:
	$a0 = { 0e01505351525657061e0e0e1f07fcb90400bf00018db69b02f3a4b8babacd213dcaca744cb82135cd212e899e }


condition:
	$a0
}