rule Trojan_Win32_Smokeloader_F_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 bc 56 c6 45 bd 69 8d 4d bc 51 } 		$a_01_1 = {4c 65 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}