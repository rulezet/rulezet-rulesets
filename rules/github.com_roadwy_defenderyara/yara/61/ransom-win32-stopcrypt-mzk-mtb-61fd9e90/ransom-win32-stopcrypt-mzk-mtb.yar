rule Ransom_Win32_StopCrypt_MZK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 75 0c c7 05 [0-08] 33 75 f8 89 75 f4 8b 45 f4 01 05 [0-04] 8b 45 f0 2b fe 8b f7 c1 e6 [0-01] 03 75 e8 03 c7 81 3d [0-04] be 01 00 00 89 45 0c 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}