rule Trojan_Win64_IceId_PBE_MTB_2{
	meta:
		description = "Trojan:Win64/IceId.PBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b c2 03 c8 8b c1 03 05 ?? ?? ?? ?? 48 98 48 8d 0d ?? ?? ?? ?? 0f be 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 68 88 04 0a e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}