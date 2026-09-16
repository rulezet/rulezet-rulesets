rule Ransom_Win32_StopCrypt_MNK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fa d3 ea 89 7c 24 24 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 ?? ?? ?? ?? 8d 44 24 20 e8 ?? ?? ?? ?? 83 eb 01 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}