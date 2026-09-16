rule Trojan_Win32_Emotet_AR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 45 17 59 8b 4d 10 43 ff 45 10 88 01 3b 1d ?? ?? ?? ?? 0f 82 } 		$a_01_1 = {8a 04 33 8b fa 33 d2 8a 0c 37 88 04 37 88 0c 33 0f b6 04 37 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}