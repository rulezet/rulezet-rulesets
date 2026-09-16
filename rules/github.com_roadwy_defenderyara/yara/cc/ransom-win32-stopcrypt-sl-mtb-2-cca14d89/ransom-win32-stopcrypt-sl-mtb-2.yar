rule Ransom_Win32_StopCrypt_SL_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 53 56 57 51 64 ff 35 30 00 00 00 58 8b 40 0c 8b 48 0c 8b 11 8b 41 30 6a 02 8b 7d ?? 57 50 e8 ?? 00 00 00 85 c0 74 } 		$a_03_1 = {55 8b ec 83 ec ?? 53 56 57 8b 45 ?? c6 00 00 83 65 ?? 00 e8 00 00 00 00 58 89 45 ?? 81 45 ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 89 48 ?? 8b 45 ?? 83 c0 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}