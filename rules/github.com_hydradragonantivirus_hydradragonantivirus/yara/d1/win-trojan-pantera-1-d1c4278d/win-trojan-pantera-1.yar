rule Win_Trojan_Pantera_1
{
strings:
	$a0 = { 7402501e06b40fcd2180fcf07503eb4690b878020c0f4003c0053000b104d3e8fa8cd9498ed9290603008cc903 }


condition:
	$a0
}