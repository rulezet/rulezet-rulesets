rule Trojan_Win64_Emotet_PAH_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa 02 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 03 01 d0 01 c0 29 c1 89 ca 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 8c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}