rule Win_Trojan_Yankee_4
{
strings:
	$a0 = { 02b603520e5143cfe800005b81 }


condition:
	$a0
}