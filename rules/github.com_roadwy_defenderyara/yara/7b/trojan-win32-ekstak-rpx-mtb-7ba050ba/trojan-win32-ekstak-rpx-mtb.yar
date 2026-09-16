rule Trojan_Win32_Ekstak_RPX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e4 f8 69 00 06 5d 66 00 00 be 0a 00 d4 bd 14 99 bc 16 66 00 00 d4 00 00 49 bd be 36 } 		$a_01_1 = {4e 00 65 00 74 00 53 00 63 00 68 00 65 00 6d 00 65 00 43 00 41 00 42 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}