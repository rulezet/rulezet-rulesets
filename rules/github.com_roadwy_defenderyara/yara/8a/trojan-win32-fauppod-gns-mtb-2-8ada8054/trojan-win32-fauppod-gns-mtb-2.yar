rule Trojan_Win32_Fauppod_GNS_MTB_2{
	meta:
		description = "Trojan:Win32/Fauppod.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 32 02 83 ec 04 c7 04 ?? ?? ?? ?? 6f 83 c4 04 83 c7 01 88 47 ff ?? 83 c2 01 68 ?? ?? ?? ?? 83 c4 04 49 53 83 c4 04 89 c0 85 c9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}