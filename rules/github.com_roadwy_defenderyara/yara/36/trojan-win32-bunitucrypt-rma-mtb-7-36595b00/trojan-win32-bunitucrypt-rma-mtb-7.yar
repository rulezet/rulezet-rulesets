rule Trojan_Win32_Bunitucrypt_RMA_MTB_7{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 6a 02 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 02 e8 ?? ?? ?? ?? 2b d8 01 1d ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 } 		$a_00_1 = {2d 00 10 00 00 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}