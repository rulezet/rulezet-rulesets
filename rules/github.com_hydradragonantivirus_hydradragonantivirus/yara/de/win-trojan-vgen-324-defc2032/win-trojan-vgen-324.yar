rule Win_Trojan_VGEN_324
{
strings:
	$a0 = { 023dbabc01cd2193b8024233c933d2cd21b9ed00be0001e84000890ed5018916d701b92600bec701e82f00890ec501 }


condition:
	$a0
}