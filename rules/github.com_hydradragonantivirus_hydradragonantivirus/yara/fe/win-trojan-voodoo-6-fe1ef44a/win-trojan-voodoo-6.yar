rule Win_Trojan_Voodoo_6
{
strings:
	$a0 = { 57bf70011e57b83f115031c050509a940c7f00bff0231e57c43e78240657ff367c24 }


condition:
	$a0
}