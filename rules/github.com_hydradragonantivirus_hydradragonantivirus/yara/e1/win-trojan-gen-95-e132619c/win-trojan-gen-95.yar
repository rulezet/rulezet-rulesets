rule Win_Trojan_Gen_95
{
strings:
	$a0 = { 02565ab91800f61446e2fbcd215e81bc }


condition:
	$a0
}