rule Win_Trojan_VS_7
{
strings:
	$a0 = { 652b6524633eab1a55a11caaa559560ff31d0f0f68841a55a1fb1caaa55603fba2d1d2a32965ed2b }


condition:
	$a0
}