rule Trojan_Win32_Bunitucrypt_RTA_MTB_7{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 45 ?? 8b 45 ?? 3b 45 ?? 73 } 		$a_03_1 = {8b d8 8b 45 ?? 03 45 ?? 03 45 ?? 03 d8 6a ?? e8 ?? ?? ?? ?? 2b d8 8b 45 ?? 31 18 6a } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}