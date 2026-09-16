rule Trojan_Win32_Malgent_C_dha{
	meta:
		description = "Trojan:Win32/Malgent.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {ff d6 8b 45 f4 8a 0c 07 ff 05 ?? ?? 00 10 2a cb 80 f1 3f 6a 00 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 } 		$a_00_1 = {74 71 5f 74 65 6c 22 23 27 71 69 69 } 		$a_01_2 = {73 73 4d 55 49 44 4c 4c 2e 64 6c 6c } 		$a_01_3 = {54 6d 44 62 67 4c 6f 67 2e 64 6c 6c } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}