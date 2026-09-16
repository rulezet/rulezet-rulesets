rule Win_Trojan_Peed_141
{
strings:
	$a0 = { f7db87da750c5589e5ad83ee0546c9c20800e87d00000068b5f5fcff56e8e4ffffff2d }


condition:
	$a0
}