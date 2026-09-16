rule Trojan_Win64_Disco_MX_MTB{
	meta:
		description = "Trojan:Win64/Disco.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d0 48 8d 8c 24 a0 02 00 00 e8 ?? ?? ?? ?? 48 8b d8 48 8d 94 24 e0 02 00 00 48 8d 8c 24 c0 02 00 00 } 		$a_00_1 = {53 45 4c 45 43 54 20 67 75 69 64 2c 20 76 61 6c 75 65 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 6c 6f 63 61 6c 5f 73 74 6f 72 65 64 5f 63 76 63 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}