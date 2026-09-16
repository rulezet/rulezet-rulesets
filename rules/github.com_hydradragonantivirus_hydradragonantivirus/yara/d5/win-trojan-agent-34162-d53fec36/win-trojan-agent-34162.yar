rule Win_Trojan_Agent_34162
{
strings:
	$a0 = { 9060e801000000c2585083c40461eb5ccc??feffff9090 }


condition:
	$a0
}