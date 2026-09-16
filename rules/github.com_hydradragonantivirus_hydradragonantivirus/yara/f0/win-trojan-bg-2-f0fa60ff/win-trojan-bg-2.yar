rule Win_Trojan_BG_2
{
strings:
	$a0 = { 48404c80f06df7d2f7d2c0c01f80e825c0c80e87cf87cf80e8ca80f0c0c0c0bec0c0dff7d2f7d2f6d0c0c8e6e901000726880547f7d2f7d249404c44480bc975b6 }


condition:
	$a0
}