rule Ransom_Win32_StopCrypt_MSK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 c1 e2 [0-01] 89 55 e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 [0-08] c7 05 [0-04] ff ff ff ff 8b 45 f4 8b 8d 40 ff ff ff d3 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}