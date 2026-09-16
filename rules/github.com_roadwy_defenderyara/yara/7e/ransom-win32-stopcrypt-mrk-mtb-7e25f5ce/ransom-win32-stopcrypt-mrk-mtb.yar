rule Ransom_Win32_StopCrypt_MRK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e0 89 45 fc 8b 45 d8 01 45 fc 8b 4d d4 8b c2 c1 e8 [0-01] 89 45 ec 8d 45 ec } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}