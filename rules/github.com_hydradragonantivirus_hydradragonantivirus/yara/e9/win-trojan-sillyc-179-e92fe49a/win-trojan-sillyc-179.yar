rule Win_Trojan_SillyC_179
{
strings:
	$a0 = { 02ba00012bd3b9530103cb8bddb440cd2133d233c9b80042cd21ba3702b90b00b440cd21eb }


condition:
	$a0
}