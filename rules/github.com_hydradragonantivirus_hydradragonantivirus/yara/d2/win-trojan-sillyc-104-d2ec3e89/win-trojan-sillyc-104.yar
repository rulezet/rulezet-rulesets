rule Win_Trojan_SillyC_104
{
strings:
	$a0 = { 4feb9e33c933d2b80242cd213d2aff73d3508bd5b9d50090b440cd2133c933d2b80042cd21 }


condition:
	$a0
}