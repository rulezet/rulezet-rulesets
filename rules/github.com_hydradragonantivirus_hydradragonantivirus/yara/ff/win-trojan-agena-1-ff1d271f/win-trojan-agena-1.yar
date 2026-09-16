rule Win_Trojan_Agena_1
{
strings:
	$a0 = { 5a75248b4408034416b91000f7e103441483d20092 }


condition:
	$a0
}