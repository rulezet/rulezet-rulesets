rule Win_Trojan_V_15
{
strings:
	$a0 = { 505351525657551e068cc80550018ed8b90205be26008a1e2400301c46e2fbe98904 }


condition:
	$a0
}