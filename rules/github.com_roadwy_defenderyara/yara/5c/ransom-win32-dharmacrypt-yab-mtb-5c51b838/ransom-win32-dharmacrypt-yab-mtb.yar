rule Ransom_Win32_DharmaCrypt_YAB_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 85 c0 0f 45 ca 89 0d 5c 55 43 00 8a 85 7c fa ff ff 30 85 8b fa ff ff 39 15 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}