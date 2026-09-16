rule Win_Trojan_Sterculius_5
{
strings:
	$a0 = { ba6102908bf2896c01eb07b91800baa40390b440e8ddfe595ab80157e8d5feb43ee8d0fe9d }


condition:
	$a0
}