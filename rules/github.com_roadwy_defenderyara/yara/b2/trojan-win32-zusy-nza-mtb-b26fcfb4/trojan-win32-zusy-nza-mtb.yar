rule Trojan_Win32_Zusy_NZA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 85 cc ff ff ff ?? ?? ?? ?? 8b 3e c7 85 f0 ff ff ff ?? ?? ?? ?? 33 fb 81 85 dc ff ff ff ?? ?? ?? ?? 89 3a 29 95 fc ff ff ff } 		$a_01_1 = {57 59 2a 44 55 5b 50 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}