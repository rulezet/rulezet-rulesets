rule Trojan_Win32_Bunitucrypt_RW_MTB_5{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 6a 0c e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 0c e8 ?? ?? ?? ?? 2b d8 01 5d ?? 83 45 ?? 04 } 		$a_00_1 = {2d 00 10 00 00 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}