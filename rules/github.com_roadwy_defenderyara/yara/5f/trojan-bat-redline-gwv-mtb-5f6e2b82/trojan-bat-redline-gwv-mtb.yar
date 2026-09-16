rule Trojan_BAT_Redline_GWV_MTB{
	meta:
		description = "Trojan:BAT/Redline.GWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 02 8e 69 32 e4 07 2a } 		$a_01_1 = {47 65 74 42 79 74 65 73 } 		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}