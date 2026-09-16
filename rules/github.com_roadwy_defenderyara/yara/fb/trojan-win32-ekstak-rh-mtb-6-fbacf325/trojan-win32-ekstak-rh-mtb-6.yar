rule Trojan_Win32_Ekstak_RH_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 57 68 88 32 65 00 e8 90 62 fb ff e9 } 		$a_01_1 = {55 8b ec 51 56 57 68 88 22 65 00 e8 90 62 fb ff e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}