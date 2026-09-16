rule Win_Trojan_Gateway_1
{
strings:
	$a0 = { ea74013e3b968502744481c274013e899681028d968402cd21b440b97101908d961301cd2132c0 }


condition:
	$a0
}