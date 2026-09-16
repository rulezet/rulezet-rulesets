rule Trojan_Win32_Ekstak_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 53 56 e8 16 65 fb ff e9 } 		$a_03_1 = {40 00 00 40 2e ?? 64 65 78 00 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}