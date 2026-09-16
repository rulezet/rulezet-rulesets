rule Win_Trojan_Agent_34678
{
strings:
	$a0 = { 515783c40433ce33cef7d18b0c2483c404e905620100570f03fe5f00000000 }


condition:
	$a0
}