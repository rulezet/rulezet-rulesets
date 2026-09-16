rule Trojan_Win64_IcedId_MG_MTB{
	meta:
		description = "Trojan:Win64/IcedId.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f af 0d ?? ?? ?? ?? 44 03 c0 48 8b 05 ?? ?? ?? ?? 49 83 c3 04 44 89 05 ?? ?? ?? ?? 41 8b d1 c1 ea 10 88 14 01 41 8b d1 8b 05 ?? ?? ?? ?? 03 c6 c1 ea 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}