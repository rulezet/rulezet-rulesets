rule Win_Trojan_NopM_1
{
strings:
	$a0 = { 0c904d02e9a600e80356019814b430cd2180fc4d751b2e3a060501734f2e8916d5022e8c1ed70251070e1fe87200 }


condition:
	$a0
}