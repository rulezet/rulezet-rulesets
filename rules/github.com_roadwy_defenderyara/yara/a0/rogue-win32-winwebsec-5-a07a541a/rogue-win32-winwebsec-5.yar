rule Rogue_Win32_Winwebsec_5{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 6a 01 6a ff 6a 23 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d 08 51 (e8|ff 15) } 		$a_00_1 = {25 73 25 73 5c 73 6d 61 72 74 66 6f 72 74 72 65 73 73 2e 65 78 65 } 		$a_00_2 = {25 73 25 73 5c 73 6d 61 72 74 70 72 6f 74 65 63 74 69 6f 6e 2e 65 78 65 } 	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}