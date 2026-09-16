rule Win_Trojan_Agent_34196
{
strings:
	$a0 = { 60c1ce05c1c6052bde5333f38bda5b6133c2f5e808000000 }


condition:
	$a0
}