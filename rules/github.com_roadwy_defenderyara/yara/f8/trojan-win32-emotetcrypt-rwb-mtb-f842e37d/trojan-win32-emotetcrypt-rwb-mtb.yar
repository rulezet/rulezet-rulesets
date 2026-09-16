rule Trojan_Win32_Emotetcrypt_RWB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {76 56 6a 51 4f 6b 50 4f 64 4b 3e 5e 46 4f 45 47 4b 6c 5e 30 51 40 7a 5f 6d 25 36 28 40 5a 76 75 65 46 5f 25 } 		$a_03_1 = {03 cf 03 ce 2b ca 8b 45 ?? 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 ?? 8b 45 } 	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}