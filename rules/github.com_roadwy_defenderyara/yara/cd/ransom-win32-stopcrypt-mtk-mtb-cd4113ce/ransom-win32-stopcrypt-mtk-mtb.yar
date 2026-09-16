rule Ransom_Win32_StopCrypt_MTK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2 } 		$a_03_1 = {55 8b ec 8b 45 0c c1 e0 [0-01] 8b 4d 08 89 01 5d c2 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}