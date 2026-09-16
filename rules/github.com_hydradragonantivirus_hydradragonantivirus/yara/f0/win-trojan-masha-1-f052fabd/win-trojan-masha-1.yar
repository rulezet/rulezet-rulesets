rule Win_Trojan_Masha_1
{
strings:
	$a0 = { 8ed78bf38be6161ffbff0e130416cd12b90602d3e05050fcb2be0752f3a5cb07be4c00bf6003 }


condition:
	$a0
}