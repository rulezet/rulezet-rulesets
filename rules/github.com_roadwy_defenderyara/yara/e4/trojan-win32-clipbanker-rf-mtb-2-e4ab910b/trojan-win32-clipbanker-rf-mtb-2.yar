rule Trojan_Win32_Clipbanker_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Clipbanker.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {73 74 66 68 6b 6c 6d 6f 70 71 79 75 68 67 6c 6a 6c 6b 6f 70 79 64 73 74 72 65 } 		$a_80_1 = {43 44 6c 67 51 75 6e 46 61 53 5a 32 } 		$a_80_2 = {65 3a 5c 47 5f 4a 4a 4a 5c 6a 6a 6a 32 30 30 38 5c 72 6f 6f 74 32 30 31 37 79 31 31 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}