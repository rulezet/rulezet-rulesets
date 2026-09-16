rule Win_Trojan_Lamento_1
{
strings:
	$a0 = { 8a261e0080f490be1e00b9640aeb039097e52e302446e2fa }


condition:
	$a0
}