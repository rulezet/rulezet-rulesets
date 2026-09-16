rule Trojan_Win32_Remcos_ARM_MTB_6{
	meta:
		description = "Trojan:Win32/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 07 8b 4f f8 05 ?? ?? ?? ?? 03 4d e8 6a 00 ff 77 fc 50 51 53 ff d6 8b 45 e4 8d 7f 28 8b 4d e0 41 } 		$a_03_1 = {03 02 03 f0 c7 45 f8 ?? ?? ?? ?? 8d 45 ec 50 6a 04 8d 45 f8 50 56 ff 75 d4 ff 15 ?? ?? ?? ?? 8b 45 c4 01 45 f8 8d 45 f8 6a 00 6a 04 50 56 ff 75 d4 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}