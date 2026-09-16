rule Ransom_Win32_StopCrypt_MVK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 05 89 4d ec 8b 55 ec 03 55 d4 89 55 ec 8b 45 e4 33 45 f0 89 45 e4 8b 4d e4 33 4d ec 89 4d e4 8b 45 e4 29 45 d0 8b 55 d8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}