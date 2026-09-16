rule Win_Trojan_92_1
{
strings:
	$a0 = { 1f33d2b97704b440cd2172d4b90100be0500ba0e008bfa8a0504288805b440cd2172bd424e75ee }


condition:
	$a0
}