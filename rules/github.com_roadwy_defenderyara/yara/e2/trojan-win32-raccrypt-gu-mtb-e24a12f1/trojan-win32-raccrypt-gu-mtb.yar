rule Trojan_Win32_Raccrypt_GU_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 04 31 83 3d ?? ?? ?? ?? 33 90 18 46 3b 35 } 		$a_02_1 = {30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 90 18 46 3b b4 24 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}