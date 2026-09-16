rule Win_Trojan_PoorMan_1
{
strings:
	$a0 = { 80bb0080530729dbcd13b403b080b500b101cd13b402b080b503cd13b403b080b502cd13b4 }


condition:
	$a0
}