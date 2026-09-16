rule Ransom_Win32_StopCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 70 89 45 [0-01] 8b 85 b0 fe ff ff 01 45 90 1b 00 8b 7d 70 8b 4d 6c 33 5d 90 1b 00 d3 ef c7 05 [0-08] 03 bd a4 fe ff ff 33 fb 81 3d [0-06] 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}