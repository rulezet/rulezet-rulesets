rule Win_Trojan_DSME_5
{
strings:
	$a0 = { cd017440fbf00072404783f4fa481f00b004011d }


condition:
	$a0
}