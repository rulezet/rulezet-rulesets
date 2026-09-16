rule Trojan_Win32_Emotetcrypt_RW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 8b 45 ?? 50 6a 00 6a ff ff 15 } 		$a_80_1 = {36 61 25 74 72 4e 3e 47 64 47 72 30 43 61 57 68 76 72 66 23 65 5f 66 70 54 76 70 67 45 2b 50 55 3f 55 34 6b 4e 4a 47 57 3f 7a 4e 3f 25 42 41 6f 52 38 46 2b } 	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}