rule Win_Trojan_Violator_2
{
strings:
	$a0 = { d00302740b803ed003037407c3cd }


condition:
	$a0
}