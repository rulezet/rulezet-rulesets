rule Trojan_Win32_Bunitucrypt_RW_MTB_12{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 ?? ?? 8b ?? ?? 3b ?? ?? 73 } 		$a_03_1 = {2b d8 8b 45 ?? 31 18 83 ?? ?? 04 83 ?? ?? 04 8b ?? ?? 3b ?? ?? 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}