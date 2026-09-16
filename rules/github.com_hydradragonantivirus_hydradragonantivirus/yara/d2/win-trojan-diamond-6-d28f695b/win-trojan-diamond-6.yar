rule Win_Trojan_Diamond_6
{
strings:
	$a0 = { cd213d032a74588bc440c1e804408cd203c28cda4a8e }


condition:
	$a0
}