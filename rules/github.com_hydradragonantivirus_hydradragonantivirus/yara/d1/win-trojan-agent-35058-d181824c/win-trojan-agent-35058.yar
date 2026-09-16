rule Win_Trojan_Agent_35058
{
strings:
	$a0 = { 68ac3000108d857cffffff6a5c508d857cffffff68a430001050ff1574100010 }


condition:
	$a0
}