rule Ransom_Win32_StopCrypt_MRK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 8b fe d3 ef 89 45 f4 03 7d d8 33 f8 81 fa [0-04] 75 } 		$a_03_1 = {8b 4d dc 8b c3 c1 e8 ?? 89 45 f0 8d 45 f0 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}