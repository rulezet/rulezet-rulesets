rule Win_Trojan_Nohoper_4
{
strings:
	$a0 = { e8000000008b14244483c40381ea05204000525deb0058899d }


condition:
	$a0
}