rule Ransom_Win32_StopCrypt_MNK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 fc [0-04] 8b 45 0c 8b 4d fc d3 e8 8b 4d 08 89 01 8b e5 5d c2 } 		$a_03_1 = {55 8b ec 51 c7 45 fc [0-04] 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 8b 4d 08 89 01 8b e5 5d c2 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}