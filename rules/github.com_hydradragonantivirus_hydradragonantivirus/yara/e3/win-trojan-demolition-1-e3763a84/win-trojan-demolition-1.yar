rule Win_Trojan_Demolition_1
{
strings:
	$a0 = { 178a04d0e09c81c60106b902069dd0149c4ee2f9 }


condition:
	$a0
}