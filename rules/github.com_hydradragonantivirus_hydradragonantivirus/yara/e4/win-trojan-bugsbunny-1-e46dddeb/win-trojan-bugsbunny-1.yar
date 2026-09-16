rule Win_Trojan_BugsBunny_1
{
strings:
	$a0 = { ba1001cd217301c3b90700bf1b01be9e00f3a4be0901bf1b01b90700fcf3a67445b8023dba9e00cd21a319 }


condition:
	$a0
}