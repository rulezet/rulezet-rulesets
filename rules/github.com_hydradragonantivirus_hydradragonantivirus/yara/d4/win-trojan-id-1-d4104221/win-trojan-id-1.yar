rule Win_Trojan_ID_1
{
strings:
	$a0 = { b9a60090b440cd212bf7897501c605e833c98bd1b80042cd21ba0300b103b440cd21b43ecd211f }


condition:
	$a0
}