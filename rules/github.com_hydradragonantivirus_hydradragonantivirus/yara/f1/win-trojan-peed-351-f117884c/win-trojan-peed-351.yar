rule Win_Trojan_Peed_351
{
strings:
	$a0 = { 81fbf0af0d007f1ac21000b957c925ff4881c1ff45da00ba08080080c1 }


condition:
	$a0
}