rule Win_Trojan_Gula_1
{
strings:
	$a0 = { 030089860a01b440b92b018bd583ea12cd2133c933d2b80042cd21b440b90300ba090103d5cd21 }


condition:
	$a0
}