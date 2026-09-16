rule Trojan_Win32_Trickbot_GKM_MTB_19{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 c1 40 f7 d9 8a 4c 0a ?? 88 88 ?? ?? ?? ?? eb ?? c6 83 ?? ?? ?? ?? 00 43 83 fb 3d 7f ?? c6 83 ?? ?? ?? ?? 01 eb } 		$a_00_1 = {71 62 77 43 2b 3c 46 24 7a 40 49 76 33 70 5f } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}