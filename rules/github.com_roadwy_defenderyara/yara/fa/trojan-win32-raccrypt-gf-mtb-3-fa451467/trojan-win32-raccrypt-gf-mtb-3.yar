rule Trojan_Win32_Raccrypt_GF_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {be 14 4a 0a c7 84 24 ?? ?? ?? ?? 32 f5 41 2a c7 84 24 ?? ?? ?? ?? 52 89 eb 0e c7 84 24 ?? ?? ?? ?? fc 7d 9a 60 c7 84 24 ?? ?? ?? ?? e5 9a 40 22 } 		$a_02_1 = {ce 07 14 68 c7 44 24 ?? 95 70 b0 07 c7 44 24 ?? db 42 40 19 c7 44 24 ?? 2f 73 f1 3c c7 44 24 ?? 16 a9 ca 74 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}