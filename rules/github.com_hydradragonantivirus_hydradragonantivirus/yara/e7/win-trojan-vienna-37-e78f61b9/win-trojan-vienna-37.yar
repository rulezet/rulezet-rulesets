rule Win_Trojan_Vienna_37
{
strings:
	$a0 = { fe81c70500890581c1c6028bfe81efc401890db95302908bd681eac601b440cd21721f3d5302 }


condition:
	$a0
}