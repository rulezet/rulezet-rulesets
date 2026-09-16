rule Ransom_Win32_DharmaCrypt_YAC_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 74 24 54 8a 44 24 27 8b 4c 24 3c 8b 7c 24 4c 8b 2d ?? ?? ?? ?? 32 c3 03 5c 24 5c 88 01 8b 44 24 34 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}