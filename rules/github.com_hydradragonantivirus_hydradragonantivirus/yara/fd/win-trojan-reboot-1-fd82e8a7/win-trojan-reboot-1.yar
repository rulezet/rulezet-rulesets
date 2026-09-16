rule Win_Trojan_Reboot_1
{
strings:
	$a0 = { 26051e003946287c07e84a007302cd19c3e83100ffe78b46093b4610c38a46008805c3 }


condition:
	$a0
}