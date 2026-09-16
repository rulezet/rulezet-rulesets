rule Ransom_Win32_StopCrypt_MYK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2 } 		$a_01_1 = {55 8b ec 8b 45 10 8b 4d 08 c1 e8 05 03 45 0c 89 01 5d c2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}