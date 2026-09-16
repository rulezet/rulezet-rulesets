rule Win_Trojan_C_9
{
strings:
	$a0 = { f0908ec026a0feff3cfc7545b42acd2180fa03753c33dbb003b91300cd26 }


condition:
	$a0
}