rule Trojan_Win32_VBInject_BS_MTB_2{
	meta:
		description = "Trojan:Win32/VBInject.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 45 dc 01 00 00 00 c7 45 e0 01 00 00 00 83 65 e8 00 eb ?? 8b 45 e8 03 45 e0 89 45 e8 8b 45 e8 3b 45 dc 7f ?? eb ?? e8 ?? ?? ?? ?? 32 32 8b 45 08 8b 00 ff 75 08 ff } 		$a_00_1 = {b9 ee ff ff 00 d9 d0 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}