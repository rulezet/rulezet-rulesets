rule Trojan_Win32_Smokeloader_F_MTB_4{
	meta:
		description = "Trojan:Win32/Smokeloader.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c6 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c6 83 c4 08 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72 } 		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}