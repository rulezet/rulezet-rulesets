rule Trojan_Win32_Neoreblamy_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0 83 bc 05 ?? ?? ff ff 00 7c 72 } 		$a_01_1 = {ff 75 14 ff 75 08 68 99 27 00 00 68 2c 0d 00 00 ff 75 0c 6a 00 68 67 11 00 00 68 20 64 00 00 ff 75 10 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}