rule Trojan_Win32_Bunitucrypt_RMA_MTB_3{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 33 c0 89 ?? ?? 33 c0 } 		$a_03_1 = {01 02 8b 45 ?? 03 [0-05] 03 [0-05] 8b ?? ?? 31 02 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}