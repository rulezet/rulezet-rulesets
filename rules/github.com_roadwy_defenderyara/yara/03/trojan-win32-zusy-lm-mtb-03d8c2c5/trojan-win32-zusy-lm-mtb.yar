rule Trojan_Win32_Zusy_LM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0f 0f b6 47 01 c1 e1 08 03 c8 0f b6 47 02 c1 e1 08 03 c8 0f b6 47 03 c1 e1 08 41 03 c1 89 03 0f b6 4f 04 0f b6 47 05 c1 e1 08 03 c8 0f b6 47 06 c1 e1 08 03 c8 } 		$a_81_1 = {41 64 76 44 69 73 6b 4c 6f 63 6b 65 72 5f 72 69 6e 67 33 } 	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*10) >=30
 
}