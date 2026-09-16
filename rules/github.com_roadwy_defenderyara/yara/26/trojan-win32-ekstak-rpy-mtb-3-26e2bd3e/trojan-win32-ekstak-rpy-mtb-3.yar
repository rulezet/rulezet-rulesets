rule Trojan_Win32_Ekstak_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 e6 68 00 4a 4a 65 00 00 be 0a 00 d4 bd 14 99 e2 03 65 00 00 d4 00 00 4a 13 13 bb } 		$a_01_1 = {2f f4 69 00 51 58 66 00 00 be 0a 00 d4 bd 14 99 f3 11 66 00 00 d4 00 00 60 0b c7 e8 } 		$a_01_2 = {4e 00 65 00 74 00 53 00 63 00 68 00 65 00 6d 00 65 00 43 00 41 00 42 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}