rule Trojan_Win64_Emotet_ED_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 6c 24 48 08 81 44 24 48 e7 d4 00 00 6b 44 24 48 0f 89 44 24 48 81 74 24 48 ff 94 0d 00 44 8b 44 24 48 8b 54 24 58 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}