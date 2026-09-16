rule Win_Trojan_Ginwui_1
{
strings:
	$a0 = { 5351b3015468190002006a00682c5e40006802000080e8b9dbffff85c0750b8b042450e89cdbffff }


condition:
	$a0
}