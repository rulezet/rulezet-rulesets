rule Win_Trojan_Miny_7
{
strings:
	$a0 = { 5152b04033d2b91f02e83cffb000e8b700b040ba1e02b90400e82cff5a5983c91fb80157cd21 }


condition:
	$a0
}