rule Win_Trojan_Agent_34165
{
strings:
	$a0 = { 60e801000000c15b5383c40461eb5ccc }


condition:
	$a0
}