rule Trojan_Win64_Emotet_PBF_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca [0-60] 48 63 c9 48 8b 54 24 28 88 04 0a e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}