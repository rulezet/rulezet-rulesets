rule Win_Trojan_Kim_1
{
strings:
	$a0 = { 7ff443f1237df55acfb0f77a6021f7dbf87fcb55b27eff817d0a27ff85620a2ccb76f4a9fcbd37b3 }


condition:
	$a0
}