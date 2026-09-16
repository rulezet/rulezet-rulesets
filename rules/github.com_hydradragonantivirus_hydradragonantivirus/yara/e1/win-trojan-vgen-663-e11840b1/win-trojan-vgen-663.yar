rule Win_Trojan_VGEN_663
{
strings:
	$a0 = { fa8ed0bc007cfb2e832e1304012ea11304b106d3e02d10008ec0be007c0e1fb900018bf9f2a5b830010650cbeb2c }


condition:
	$a0
}