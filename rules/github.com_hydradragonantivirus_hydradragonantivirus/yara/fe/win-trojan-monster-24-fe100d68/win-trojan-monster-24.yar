rule Win_Trojan_Monster_24
{
strings:
	$a0 = { 02bede2cfc300446e2fb25cdcd934e23ce250dcc00ed0b89dc3326cd0b89dccd2547cc4649f5cf6ecdcc4749 }


condition:
	$a0
}