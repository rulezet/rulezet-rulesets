rule Trojan_Win32_Ekstak_RPY_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 d5 69 00 69 39 66 00 00 be 0a 00 d4 bd 14 99 ff f2 65 00 00 d4 00 00 ce 39 aa 43 } 		$a_01_1 = {50 00 52 00 69 00 6e 00 67 00 54 00 6f 00 6e 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}