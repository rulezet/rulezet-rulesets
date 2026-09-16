rule Trojan_Win32_Ekstak_RC_MTB_17{
	meta:
		description = "Trojan:Win32/Ekstak.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 e8 a9 96 20 00 56 ff 15 a8 51 65 00 ff 15 ac 51 65 00 e9 } 		$a_01_1 = {46 00 69 00 6c 00 65 00 41 00 6c 00 79 00 7a 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}