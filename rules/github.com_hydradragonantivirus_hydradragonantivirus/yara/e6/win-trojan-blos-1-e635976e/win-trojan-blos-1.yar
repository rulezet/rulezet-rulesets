rule Win_Trojan_Blos_1
{
strings:
	$a0 = { 0300b9ffffac4975fd0e0e1f07be2a0003f58bfeb913048a04341226880546474975f4 }


condition:
	$a0
}