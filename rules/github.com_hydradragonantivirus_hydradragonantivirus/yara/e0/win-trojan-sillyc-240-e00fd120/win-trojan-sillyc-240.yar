rule Win_Trojan_SillyC_240
{
strings:
	$a0 = { e800005d83ed038db6750056b90200f3a55fb44e8bd6cd217256b8023dba9e00cd21 }


condition:
	$a0
}