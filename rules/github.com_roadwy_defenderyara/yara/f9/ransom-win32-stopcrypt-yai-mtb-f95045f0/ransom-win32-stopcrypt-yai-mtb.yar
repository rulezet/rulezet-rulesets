rule Ransom_Win32_Stopcrypt_YAI_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8b 55 f4 33 45 ec 81 c3 ?? ?? ?? ?? 8b 4d dc 2b f0 89 45 f8 89 75 fc 4f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}