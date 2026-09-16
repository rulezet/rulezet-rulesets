rule Win_Trojan_Silly_50
{
strings:
	$a0 = { cd21726bba9b02b8023d90cd21a31401 }


condition:
	$a0
}