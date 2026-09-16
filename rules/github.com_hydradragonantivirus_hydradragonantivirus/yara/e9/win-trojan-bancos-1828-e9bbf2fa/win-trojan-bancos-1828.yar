rule Win_Trojan_Bancos_1828
{
strings:
	$a0 = { 4cf8938592d62455c76fbf0d414ef91c8810f2c3ead508af5c399c7bc050daadf1f1afd272278c4460540344cff75760a74b03ed123adf76b3d38e96ee7f9143a5a743a5ede6 }


condition:
	$a0
}