rule Win_Trojan_Gen_238
{
strings:
	$a0 = { 8249f2ecdaecfd3d38f37a2e9ac1f015c4f4b44fcbf38eccf022ecdd9048ccf0b7b305ccf0 }


condition:
	$a0
}