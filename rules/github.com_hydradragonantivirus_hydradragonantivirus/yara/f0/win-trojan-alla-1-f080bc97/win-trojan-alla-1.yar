rule Win_Trojan_Alla_1
{
strings:
	$a0 = { 7cfa8be68ed0fbbf1304832d02cd12b30686d9d3e08ec0c7068e000001c7069200010133c0cd }


condition:
	$a0
}