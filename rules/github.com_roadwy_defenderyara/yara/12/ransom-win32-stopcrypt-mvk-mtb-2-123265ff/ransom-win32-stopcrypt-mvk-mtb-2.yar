rule Ransom_Win32_StopCrypt_MVK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 33 44 24 [0-01] c2 [0-02] 81 00 [0-04] c3 } 		$a_03_1 = {c1 e0 04 89 01 c3 81 00 [0-04] c3 29 08 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}