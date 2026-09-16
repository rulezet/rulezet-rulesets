rule Win_Trojan_ChaosYears_1
{
strings:
	$a0 = { 4b7506e8f102e97b0080fc3d7506e84d04e9700080fc }


condition:
	$a0
}