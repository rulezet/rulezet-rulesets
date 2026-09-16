rule Win_Trojan_CPP_1
{
strings:
	$a0 = { 5760beff00037501fc66a533c98ec1bf0402b1e726803dbf741cf3a48ed966a1840066a3ce0266a3040066a30c }


condition:
	$a0
}