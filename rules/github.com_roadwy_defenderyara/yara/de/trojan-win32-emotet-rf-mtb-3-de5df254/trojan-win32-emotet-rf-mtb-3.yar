rule Trojan_Win32_Emotet_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_81_0 = {28 5e 74 4d 4b 26 31 36 76 34 41 32 48 53 21 24 70 71 4b 76 43 53 30 41 57 3c 76 6e 6c 6e 6a 69 76 52 53 50 36 6d 4d 31 65 4e 32 53 71 6e 47 63 53 29 2a 6d 5a 73 6f 37 4d 45 57 4c 52 77 6b 6d 6b 49 31 } 		$a_03_1 = {33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 75 ?? 2b f2 2b f1 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 4d ?? 88 04 31 e9 } 	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*5) >=6
 
}