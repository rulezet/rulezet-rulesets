rule Trojan_Win32_Ekstak_RB_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f0 11 f7 d8 1b c0 40 83 c4 ?? c3 33 c0 5f 83 c4 } 		$a_01_1 = {55 8b ec 51 56 e8 f6 69 fb ff e9 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}