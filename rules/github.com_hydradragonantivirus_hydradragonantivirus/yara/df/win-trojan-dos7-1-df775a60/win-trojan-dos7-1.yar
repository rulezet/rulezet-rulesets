rule Win_Trojan_Dos7_1
{
strings:
	$a0 = { 068ed88ec0be8400bf0c00a5a5071f8cd880c4108ec0bf00018bf7b95601f3a48ed8b829011e50cbb41a99ccb44eb53fbad701cc7229b8023dba1e00cc7226 }


condition:
	$a0
}