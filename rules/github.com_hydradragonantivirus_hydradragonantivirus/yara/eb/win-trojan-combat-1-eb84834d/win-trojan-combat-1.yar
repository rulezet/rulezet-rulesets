rule Win_Trojan_ComBat_1
{
strings:
	$a0 = { 030189462889eab98e01b440cd2133c933d2b80042cd218d5627b90300b440cd21c3c746100001 }


condition:
	$a0
}