rule Trojan_Win32_Emotet_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {64 66 3f 2a 61 33 74 72 37 6d 78 36 42 4a 72 73 37 3c 66 62 54 25 59 28 64 75 4a 28 4d 76 6a 52 40 30 64 41 62 35 21 51 6d 36 37 29 36 43 4b 76 77 55 68 37 4f 55 72 30 55 5f 72 58 46 68 4f 77 54 29 24 6b 48 39 71 77 24 55 40 6b } 		$a_03_1 = {83 c5 40 55 68 00 30 00 00 56 53 6a ff ff 15 ?? ?? ?? ?? eb } 	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}