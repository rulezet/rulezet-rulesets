rule Trojan_Win32_Marijku_A{
	meta:
		description = "Trojan:Win32/Marijku.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 78 0c 64 26 08 00 74 09 c7 46 18 0d 00 00 c0 eb 22 57 68 ?? ?? 01 00 57 57 57 68 ff 03 1f 00 } 		$a_03_1 = {6a 1b 8d 7e 38 59 b8 ?? ?? 01 00 f3 ab c7 46 34 ?? ?? 01 00 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 53 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}