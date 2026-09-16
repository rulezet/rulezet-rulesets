rule Trojan_Win32_Ekstak_RE_MTB_5{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 e8 36 65 fb ff e9 } 		$a_01_1 = {53 8b 1d e4 33 65 00 56 8b 74 24 0c 57 6a 00 6a 00 6a 00 8d 46 1c 83 cf ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}