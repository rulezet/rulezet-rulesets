rule Ransom_Win32_StopCrypt_SK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 1f 33 4d ?? 89 35 ?? ?? ?? ?? 33 4d ?? 89 4d ?? 8b 45 } 		$a_03_1 = {8b ec 8b 45 ?? 8b 4d ?? 31 08 5d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}