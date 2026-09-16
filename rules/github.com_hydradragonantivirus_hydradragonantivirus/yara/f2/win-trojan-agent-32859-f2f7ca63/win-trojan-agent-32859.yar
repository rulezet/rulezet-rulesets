rule Win_Trojan_Agent_32859
{
strings:
	$a0 = { a25ae0f19f20bb72802c5d6a0fc9456500bbd048ce4b3bc659e0bfdda65b838aa2f2504964809a68bd26afe7fe8432659c2ccf0a27a6e956d901de4ea34b111a27b7fd6c58afea4f91b59dc75c494d96 }


condition:
	$a0
}