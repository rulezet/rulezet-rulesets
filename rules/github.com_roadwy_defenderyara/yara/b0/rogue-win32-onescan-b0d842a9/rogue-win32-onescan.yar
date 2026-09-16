rule Rogue_Win32_Onescan{
	meta:
		description = "Rogue:Win32/Onescan,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {76 61 63 63 69 6e 65 [0-10] 72 65 73 65 72 76 61 74 69 6f 6e 00 25 79 25 6d 25 64 } 		$a_01_1 = {76 61 63 63 69 6e 65 5f 42 6c 6f 63 6b 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}