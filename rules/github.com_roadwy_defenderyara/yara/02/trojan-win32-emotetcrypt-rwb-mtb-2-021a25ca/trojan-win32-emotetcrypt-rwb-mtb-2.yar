rule Trojan_Win32_Emotetcrypt_RWB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 8b 95 ?? ?? ?? ?? 52 6a 00 6a ff ff 15 } 		$a_80_1 = {28 52 30 3c 6d 3c 73 61 3f 68 25 32 78 43 6a 62 37 21 64 44 47 24 2a 65 34 2a 69 38 70 21 33 55 75 74 6d 2a 67 42 76 43 79 34 72 4d 64 72 33 46 7a 66 67 29 } 	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}