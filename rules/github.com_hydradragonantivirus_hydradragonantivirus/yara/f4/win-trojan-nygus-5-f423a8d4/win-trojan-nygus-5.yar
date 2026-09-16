rule Win_Trojan_Nygus_5
{
strings:
	$a0 = { 8ec08bd826803e00005a75ec33c0abbf0300268b053d40 }


condition:
	$a0
}