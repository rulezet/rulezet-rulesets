rule Ransom_Win32_StopCrypt_SM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 4d fc 89 4d ?? 8b 45 ?? 01 05 } 		$a_03_1 = {8b c3 c1 e0 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}