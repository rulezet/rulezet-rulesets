rule Trojan_Win64_Emotet_BD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 1f 42 32 04 27 41 88 44 3d 00 48 ff c7 48 81 ff ?? ?? ?? ?? 0f 85 5d ff ff ff } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}