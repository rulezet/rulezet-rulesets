rule Win_Trojan_Silly_44
{
strings:
	$a0 = { 088905b440b1718d960301cd21e80e00b4404fe80100c3b10389facd21c3b8023dba9e00cd21 }


condition:
	$a0
}