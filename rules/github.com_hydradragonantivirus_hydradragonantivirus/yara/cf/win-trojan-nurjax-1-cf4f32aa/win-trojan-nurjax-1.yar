rule Win_Trojan_Nurjax_1
{
strings:
	$a0 = { f8f3f39a01cdbce5b1eb19435a3e0c725019ff3c60c89b1c1a5a868a885b956429b68f573ef1a2460e5bc29536 }


condition:
	$a0
}