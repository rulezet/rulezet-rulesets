rule _RosAsm_2050a__Betov_
{
	meta:
		description = "RosAsm 2050a -> Betov"
	strings:
		$0 = {55 8B EC 60 8B 5D 08 B9 08 00 00 00 BF ?? ?? ?? ?? 83 C7 07 FD 8A C3 24 0F 04 30 3C 39 76 02 04 07 AA C1 EB 04 E2 EE FC 68 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 61 8B E5 5D C2 04 00}
	condition:
		$0
}