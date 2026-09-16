rule Trojan_Win32_Emotetcrypt_GI_MTB_3{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b c1 0f af c3 83 c0 02 0f af c7 83 c0 02 0f af 05 ?? ?? ?? ?? 2b f0 8d 44 1b 02 0f af c3 03 44 24 2c 2b f1 0f af 0d ?? ?? ?? ?? 2b f7 8d 14 72 03 c2 8d 0c 89 0f b6 14 01 8b 44 24 20 30 10 } 		$a_81_1 = {21 50 21 38 68 21 61 74 2a 68 64 53 74 3c 61 39 45 6b 40 62 46 36 21 76 75 4b 6a 6e 78 74 64 39 55 2b 5e 52 46 66 25 49 26 24 48 39 78 5e 23 35 6e 48 3e 5f 43 73 47 71 6d 35 59 54 78 5f 76 69 45 28 37 39 51 75 2b 58 45 4f 30 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}