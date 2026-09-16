rule Win_Trojan_V_24
{
strings:
	$a0 = { 90909090cd21b41189facd213c007402cd20b84000bf5106403d5b00741ffcaa50b411cd213c007404584febeb }


condition:
	$a0
}