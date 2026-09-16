rule Win_Trojan_Gen_202
{
strings:
	$a0 = { f2e8b7fae8d0f0e808e53c017535bff23f1e57bf8c1c }


condition:
	$a0
}