rule Trojan_Win64_Emotet_BL_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 ca 48 63 c9 48 8b 15 ?? ?? ?? ?? 88 04 0a e9 } 		$a_01_1 = {03 f9 8b cf 03 d1 8b ca } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}