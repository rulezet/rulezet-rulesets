rule Win_Trojan_Paz_1
{
strings:
	$a0 = { e8070058050001e945008bf0b90b04311c4646e2fac3 }


condition:
	$a0
}