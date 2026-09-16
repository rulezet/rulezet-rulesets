rule Win_Trojan_Baba_4
{
strings:
	$a0 = { 8cc88ed8b44033d2b9640190cd2133c933d2b80042cd21b440ba5101b90400cd21b43ecd215a }


condition:
	$a0
}