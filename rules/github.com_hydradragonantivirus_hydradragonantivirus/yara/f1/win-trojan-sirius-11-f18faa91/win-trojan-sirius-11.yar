rule Win_Trojan_Sirius_11
{
strings:
	$a0 = { e800005d81ed08018db62601e80200eb108b962503b9ff01 }


condition:
	$a0
}