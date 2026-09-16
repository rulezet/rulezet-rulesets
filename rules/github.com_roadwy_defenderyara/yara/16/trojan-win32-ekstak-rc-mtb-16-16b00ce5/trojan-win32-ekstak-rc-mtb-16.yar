rule Trojan_Win32_Ekstak_RC_MTB_16{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 e8 6b a0 20 00 56 ff 15 54 66 65 00 ff 15 58 66 65 00 e9 } 		$a_01_1 = {46 00 6f 00 6c 00 64 00 41 00 6c 00 79 00 7a 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}