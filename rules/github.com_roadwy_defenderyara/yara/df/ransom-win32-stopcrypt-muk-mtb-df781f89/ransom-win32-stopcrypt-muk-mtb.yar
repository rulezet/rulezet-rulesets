rule Ransom_Win32_StopCrypt_MUK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f0 89 44 24 10 89 74 24 1c 8b 44 24 1c 01 05 [0-04] 8b 44 24 1c 29 44 24 14 8b 44 24 14 c1 e0 [0-01] 89 44 24 10 8b 44 24 30 01 44 24 10 8b 44 24 14 03 44 24 20 89 44 24 18 81 3d [0-06] 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}