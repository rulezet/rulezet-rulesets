rule Trojan_Win32_Smokeloader_F_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b0 15 31 01 8b 0a 01 ad c2 15 f1 7b } 		$a_01_1 = {26 08 01 01 7b 3e 8a db 01 8b 0e 01 ad c2 b9 15 66 01 8b 0a 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}