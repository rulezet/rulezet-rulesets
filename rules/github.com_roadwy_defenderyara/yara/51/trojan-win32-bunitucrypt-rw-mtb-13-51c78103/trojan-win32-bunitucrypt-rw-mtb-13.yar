rule Trojan_Win32_Bunitucrypt_RW_MTB_13{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 45 ?? 89 45 ?? 8b 45 ?? 8b 55 ?? 89 10 6a 01 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } 		$a_03_1 = {2d 00 10 00 00 [0-05] 83 45 [0-05] 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}