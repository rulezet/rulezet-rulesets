rule Trojan_Win32_Emotetcrypt_GI_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 8b 4d ?? 8b 51 ?? 52 8b 45 ?? 8b 48 ?? 51 ff 15 } 		$a_00_1 = {f3 a4 8b 44 24 0c 5e 5f c3 } 		$a_00_2 = {83 c4 0c 8b 4d f0 83 c1 28 89 4d f0 eb } 		$a_00_3 = {89 45 fc 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 55 fc } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}