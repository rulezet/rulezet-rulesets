rule Ransom_Win32_StopCrypt_MK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e1 [0-01] 03 8d [0-02] ff ff 81 3d [0-06] 00 00 90 13 8b 5d [0-01] 03 d8 c1 e8 [0-01] 89 45 [0-01] c7 05 [0-08] 8b 85 [0-02] ff ff 01 45 [0-01] 81 3d [0-06] 00 00 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}