rule Trojan_Win32_Raccrypt_GF_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_02_0 = {88 04 31 81 3d ?? ?? ?? ?? 03 02 00 00 } 		$a_02_1 = {88 14 30 81 3d ?? ?? ?? ?? 03 02 00 00 } 		$a_02_2 = {8b 4c 24 10 30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 90 18 46 3b b4 24 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*4) >=5
 
}