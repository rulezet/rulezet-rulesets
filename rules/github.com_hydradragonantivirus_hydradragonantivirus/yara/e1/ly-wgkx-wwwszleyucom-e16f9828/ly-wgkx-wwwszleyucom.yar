rule _LY_WGKX__wwwszleyucom_
{
	meta:
		description = "LY_WGKX -> www.szleyu.com"
	strings:
		$0 = {4D 79 46 75 6E 00 62 73}
	condition:
		$0
}