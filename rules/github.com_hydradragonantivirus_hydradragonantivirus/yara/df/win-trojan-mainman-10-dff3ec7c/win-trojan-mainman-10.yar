rule Win_Trojan_Mainman_10
{
strings:
	$a0 = { b9380001ca81ed0601b81900cd073d86f3742cb80fffcd213d0101742acd06b88462bb0300b90010cd2f55b8 }


condition:
	$a0
}