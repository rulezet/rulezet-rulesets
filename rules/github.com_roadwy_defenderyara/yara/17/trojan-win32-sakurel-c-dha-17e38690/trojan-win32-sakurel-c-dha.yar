rule Trojan_Win32_Sakurel_C_dha{
	meta:
		description = "Trojan:Win32/Sakurel.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 40 01 00 59 5b 6a 69 68 70 2e 6d 73 68 73 65 74 75 54 ff 35 ?? ?? ?? ?? e8 } 		$a_00_1 = {31 c0 8a 04 0b 3c 00 74 09 38 d0 74 05 30 d0 88 04 0b 83 f9 00 74 03 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}