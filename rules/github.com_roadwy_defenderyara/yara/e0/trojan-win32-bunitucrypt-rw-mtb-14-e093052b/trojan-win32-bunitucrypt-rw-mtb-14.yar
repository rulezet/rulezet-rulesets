rule Trojan_Win32_Bunitucrypt_RW_MTB_14{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83 } 		$a_03_1 = {2b d8 a1 94 ?? ?? ?? 31 18 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}