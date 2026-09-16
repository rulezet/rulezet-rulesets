rule Win_Trojan_Turbo_4
{
strings:
	$a0 = { 038c064003bab200b82125cd211f2e80be4c035a75 }


condition:
	$a0
}