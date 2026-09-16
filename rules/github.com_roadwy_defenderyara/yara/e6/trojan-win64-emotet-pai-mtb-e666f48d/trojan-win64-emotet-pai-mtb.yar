rule Trojan_Win64_Emotet_PAI_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 44 8b 45 ?? 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 ?? 41 31 d2 45 88 d3 48 8b 8d ?? ?? ?? ?? 4c 63 8d ?? ?? ?? ?? 46 88 1c 09 8b 85 ?? ?? ?? ?? 83 c0 01 89 85 ?? ?? ?? ?? e9 } 		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}