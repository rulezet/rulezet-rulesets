rule Trojan_Win32_Emotetcrypt_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {43 72 36 69 57 65 4e 71 62 48 69 70 5a 63 65 62 73 6f 48 32 58 54 76 57 42 66 79 3f 39 21 55 70 48 6a 6d 48 30 74 30 72 31 46 36 69 4a 75 28 48 7a 3e 38 2b 34 42 21 51 39 53 63 70 52 56 67 79 6f 76 4c 65 23 78 28 55 37 7a 42 30 30 43 6d 7a 30 3e 79 6e 6c 24 23 5f 55 37 40 6a 50 3f 40 29 63 41 78 65 71 55 30 49 32 78 74 5e 73 24 } 		$a_03_1 = {b9 20 1f 00 00 f7 f1 8b 45 ?? 03 55 ?? 8b 4d ?? 0f b6 04 02 8b 55 ?? 30 04 0a 41 89 4d ?? 3b cf b9 20 1f 00 00 72 } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}