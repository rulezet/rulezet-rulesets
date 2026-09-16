rule Win_Trojan_V_8
{
strings:
	$a0 = { 8c062a020e1fb9da00be09036a5407e8b6002ec7060e02faff2eff2e160234c325a218f53aac88 }


condition:
	$a0
}