rule Ransom_Win32_StopCrypt_MSK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 } 		$a_03_1 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 [0-04] c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}