rule Ransom_Win32_StopCrypt_MZK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 c1 e8 ?? 89 45 ec 8b 45 ec 03 45 d4 89 45 ec 8b 45 e4 33 45 f0 89 45 e4 8b 45 e4 33 45 ec 89 45 e4 8b 45 e4 29 45 d0 ff 75 d8 8d 45 e8 50 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}