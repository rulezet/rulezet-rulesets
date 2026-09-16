rule Win_Trojan_Agent_35861
{
strings:
	$a0 = { 68d6000000411bc15033d80bd023d646520bd84f03d72bc633de5303cb0bfb23 }


condition:
	$a0
}