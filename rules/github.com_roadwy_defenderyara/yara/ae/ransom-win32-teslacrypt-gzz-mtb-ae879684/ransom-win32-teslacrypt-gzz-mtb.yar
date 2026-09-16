rule Ransom_Win32_TeslaCrypt_GZZ_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 7c 81 f1 5c 4b 00 00 03 4c 24 50 89 4c 24 50 2b 44 24 7c 39 44 24 50 ?? ?? 8a 44 24 34 0c 7e 88 84 24 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}