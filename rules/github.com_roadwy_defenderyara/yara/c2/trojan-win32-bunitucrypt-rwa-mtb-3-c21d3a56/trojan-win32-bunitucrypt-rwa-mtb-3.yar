rule Trojan_Win32_Bunitucrypt_RWA_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 0f 83 } 		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 6a ?? e8 ?? ?? ?? ?? 8b d8 83 c3 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}