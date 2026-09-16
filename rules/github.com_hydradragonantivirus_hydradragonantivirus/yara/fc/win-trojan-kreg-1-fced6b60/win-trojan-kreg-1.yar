rule Win_Trojan_Kreg_1
{
strings:
	$a0 = { 80f7db8fc9c438bc63bf9fc312b05fbd28ad0802c585778022f7379fbb2901b8138d658823a6dc0a }


condition:
	$a0
}