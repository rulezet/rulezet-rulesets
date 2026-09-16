rule Win_Trojan_Haxspy_7
{
strings:
	$a0 = { 50505468368a4000680401000068d2874000e8f6010000 }


condition:
	$a0
}