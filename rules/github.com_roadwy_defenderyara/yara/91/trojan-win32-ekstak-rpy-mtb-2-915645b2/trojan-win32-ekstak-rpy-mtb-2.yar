rule Trojan_Win32_Ekstak_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f2 9f 69 00 14 04 66 00 00 be 0a 00 d4 bd 14 99 c0 bd 65 00 00 d4 00 00 91 fb b8 1a } 		$a_01_1 = {50 00 52 00 69 00 6e 00 67 00 54 00 6f 00 6e 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}