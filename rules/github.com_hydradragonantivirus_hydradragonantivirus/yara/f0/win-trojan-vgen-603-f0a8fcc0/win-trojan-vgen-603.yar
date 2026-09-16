rule Win_Trojan_VGEN_603
{
strings:
	$a0 = { 5352cd21fc89e58b7efa83ef0589fe3d525375051e07e98b00c785b40a00008c85b60a1e07b808008ed8be04008b04 }


condition:
	$a0
}