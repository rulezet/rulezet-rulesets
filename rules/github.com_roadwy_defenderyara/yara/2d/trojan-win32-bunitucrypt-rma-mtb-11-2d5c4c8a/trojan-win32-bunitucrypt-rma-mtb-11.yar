rule Trojan_Win32_Bunitucrypt_RMA_MTB_11{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-05] 0e 00 00 00 } 		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}