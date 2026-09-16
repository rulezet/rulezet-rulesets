rule Trojan_Win32_Raccrypt_GE_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 14 30 81 3d ?? ?? ?? ?? 03 02 00 00 } 		$a_02_1 = {8b 4c 24 0c 30 04 31 81 ff 91 05 00 00 90 18 46 3b f7 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}