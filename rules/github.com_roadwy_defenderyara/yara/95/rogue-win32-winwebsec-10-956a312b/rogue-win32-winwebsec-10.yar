rule Rogue_Win32_Winwebsec_10{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 6f 74 61 6c 20 53 65 63 75 72 65 20 32 30 30 39 } 		$a_01_1 = {4d 61 6c 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0d 00 00 00 53 70 79 77 61 72 65 20 46 6f 75 6e 64 00 00 00 ff ff ff ff 0d 00 00 00 41 64 77 61 72 65 20 46 6c 6f 75 6e 64 } 		$a_01_2 = {4d 61 6c 77 61 72 65 00 ff ff ff ff 07 00 00 00 53 70 79 77 61 72 65 00 ff ff ff ff 06 00 00 00 41 64 77 61 72 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}