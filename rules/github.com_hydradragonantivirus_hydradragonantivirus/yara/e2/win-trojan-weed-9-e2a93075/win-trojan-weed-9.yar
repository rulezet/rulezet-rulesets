rule Win_Trojan_Weed_9
{
strings:
	$a0 = { e6d9eadc3762306359d81277bedf56dca1ec4dde87c153dcbe9e0050da09eec232d3d20b2699 }


condition:
	$a0
}