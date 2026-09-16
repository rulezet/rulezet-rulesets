rule Win_Trojan_Kemerovo_2
{
strings:
	$a0 = { 0100b80242cd2172d15a5283ea04b90001b440cd21 }


condition:
	$a0
}