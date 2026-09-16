rule Win_Trojan_Agent_35521
{
strings:
	$a0 = { 574152455c4d41726f736f66745c57696e646f7773204e545c637572 }


condition:
	$a0
}