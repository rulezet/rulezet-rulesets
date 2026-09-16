rule Ransom_Win32_StopCrypt_MBK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 1c 01 c1 e8 05 89 45 [0-01] c7 05 [0-08] 8b 85 90 90 fd ff ff 01 45 90 1b 00 81 3d [0-06] 00 00 75 } 		$a_03_1 = {8b 45 74 31 45 [0-01] 89 3d [0-04] 8b 45 [0-01] 29 45 [0-01] 81 3d [0-06] 00 00 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}