rule Trojan_Win32_Raccrypt_GS_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 32 83 3d ?? ?? ?? ?? 33 } 		$a_02_1 = {30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 90 18 46 3b b4 24 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}