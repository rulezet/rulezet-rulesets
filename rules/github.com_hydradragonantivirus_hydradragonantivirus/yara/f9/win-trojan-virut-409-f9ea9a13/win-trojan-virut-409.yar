rule Win_Trojan_Virut_409
{
strings:
	$a0 = { 83c4e0e8b6ffffff4680cd390fc16c243039d280dc9f8b5c240c996681e30088 }


condition:
	$a0
}