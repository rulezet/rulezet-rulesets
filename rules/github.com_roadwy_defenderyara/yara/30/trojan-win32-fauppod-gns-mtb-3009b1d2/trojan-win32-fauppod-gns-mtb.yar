rule Trojan_Win32_Fauppod_GNS_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c6 01 8a 46 ff 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 47 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}