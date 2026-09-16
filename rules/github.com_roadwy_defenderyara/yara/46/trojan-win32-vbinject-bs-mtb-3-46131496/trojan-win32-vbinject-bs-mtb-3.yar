rule Trojan_Win32_VBInject_BS_MTB_3{
	meta:
		description = "Trojan:Win32/VBInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 08 8b 55 dc 2b 51 14 89 55 cc 8b 45 08 8b 08 8b 55 cc 3b 51 10 73 } 		$a_02_1 = {eb 0c ff 15 ?? ?? ?? ?? 89 85 60 ff ff ff 8b 4d d8 ff 15 ?? ?? ?? ?? 8b 4d 08 8b 11 8b 4a 0c 8b 95 60 ff ff ff 88 04 11 c7 45 fc 25 00 00 00 e9 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}