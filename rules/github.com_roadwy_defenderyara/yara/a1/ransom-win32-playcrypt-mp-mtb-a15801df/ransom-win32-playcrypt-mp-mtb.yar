rule Ransom_Win32_PlayCrypt_MP_MTB{
	meta:
		description = "Ransom:Win32/PlayCrypt.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 54 31 03 83 ef 04 0f b6 4c 31 02 c1 e2 08 0b d1 8b 4d fc c1 e2 08 0f b6 4c 31 01 0b d1 8b 4d fc c1 e2 08 0f b6 0c 31 83 c6 04 0b d1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}