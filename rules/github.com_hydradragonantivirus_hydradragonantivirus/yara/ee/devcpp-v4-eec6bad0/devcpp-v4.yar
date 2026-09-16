rule _DevCpp_v4_
{
	meta:
		description = "Dev-C++ v4"
	strings:
		$0 = {55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF}
	condition:
		$0
}