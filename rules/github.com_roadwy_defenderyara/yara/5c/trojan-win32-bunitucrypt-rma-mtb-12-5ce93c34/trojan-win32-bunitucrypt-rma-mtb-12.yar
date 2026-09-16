rule Trojan_Win32_Bunitucrypt_RMA_MTB_12{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 [0-05] 0e 00 00 00 } 		$a_03_1 = {31 02 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 [0-46] 3b 05 ?? ?? ?? ?? 72 [0-10] 2d 00 10 00 00 ?? ?? 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}