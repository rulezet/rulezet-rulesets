rule Trojan_Win32_Ekstak_RB_MTB_10{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 8b 75 14 56 6a 00 ff 15 50 67 65 00 56 e8 18 a1 20 00 e9 } 		$a_01_1 = {53 00 68 00 72 00 65 00 64 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}