rule Win_Trojan_Jerusalem_24
{
strings:
	$a0 = { acaccd213d30ac7510b8ecac2e8b0e0a01bf0001be00 }


condition:
	$a0
}