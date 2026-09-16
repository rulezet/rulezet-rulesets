rule Win_Trojan_Trivial_380
{
strings:
	$a0 = { 10008ed8b430cd213c007448b42fcd21891e5b008c065d00ba6500b41acd21b44eb90100ba5f00cd2172298026 }


condition:
	$a0
}