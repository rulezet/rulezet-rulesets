rule Win_Trojan_Deino_1
{
strings:
	$a0 = { 02586a1059fa99cd26fb6802fa586845595acd21c3fcb9 }


condition:
	$a0
}