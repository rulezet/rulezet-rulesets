rule Win_Trojan_Mange_tout_1
{
strings:
	$a0 = { 0632020e1fb9da00be11036a5407e8be002ec7061602ffff2eff2e1e0234c325a218f502ac88 }


condition:
	$a0
}