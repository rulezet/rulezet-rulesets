rule Win_Trojan_Trojan_240
{
strings:
	$a0 = { b95e012e812d271950584747e2f50f1a27767771a8063e1a7771a81574699b28b4cf251b77d1271ab2117f70cb }


condition:
	$a0
}