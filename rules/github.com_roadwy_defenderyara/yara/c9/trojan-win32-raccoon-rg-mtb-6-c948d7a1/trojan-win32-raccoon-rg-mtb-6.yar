rule Trojan_Win32_Raccoon_RG_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 7c f6 ff ff 83 c0 01 89 85 7c f6 ff ff 8b 8d 7c f6 ff ff 3b 0d ?? ?? ?? ?? 73 27 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 7c f6 ff ff 0f b6 08 33 ca 8b 15 ?? ?? ?? ?? 03 95 7c f6 ff ff 88 0a eb bc } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}