rule Trojan_Win32_Emotet_RMA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b c1 50 56 33 db 53 6a ff ff 15 ?? ?? ?? ?? 8b 6c 24 ?? eb } 		$a_80_1 = {3e 42 25 6c 49 32 28 25 61 70 40 58 5e 6b 63 3e 6f 6b 29 37 32 51 44 68 4d 50 59 30 76 5f 3e 5f 49 6e 74 66 76 3c 48 7a 49 50 55 62 52 35 32 7a 30 57 64 4a 61 26 58 33 30 79 3f 43 65 23 78 53 33 39 2b 4c 55 4a 64 3c 4f 35 66 5f } 	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}