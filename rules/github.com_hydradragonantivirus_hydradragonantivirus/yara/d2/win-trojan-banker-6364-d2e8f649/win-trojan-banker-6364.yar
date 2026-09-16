rule Win_Trojan_Banker_6364
{
strings:
	$a0 = { 558bec83c4f0b8f44b4600e87021faffa1f87c46008b00e8cccfffff8b0df07d }


condition:
	$a0
}