rule Trojan_Win32_Ekstak_RH_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 e8 b7 6a fb ff e9 } 		$a_01_1 = {40 00 00 40 2e 6d 70 67 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}