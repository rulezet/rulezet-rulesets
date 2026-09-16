rule Trojan_Win32_Emotet_KMG_MTB_14{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 08 88 0a 8b 55 08 03 55 f0 8a 45 fc 88 02 8b 4d f0 83 e9 01 89 4d f0 eb } 		$a_01_1 = {61 6d 75 4e 78 45 63 6f 6c 6c 41 6c 61 75 74 72 69 56 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}