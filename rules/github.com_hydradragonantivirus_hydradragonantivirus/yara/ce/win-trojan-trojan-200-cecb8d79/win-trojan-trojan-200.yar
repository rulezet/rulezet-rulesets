rule Win_Trojan_Trojan_200
{
strings:
	$a0 = { bf1301be4d032e8135000047474e75 }


condition:
	$a0
}