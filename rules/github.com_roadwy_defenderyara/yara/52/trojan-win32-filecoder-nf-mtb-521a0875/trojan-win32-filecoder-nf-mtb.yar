rule Trojan_Win32_FileCoder_NF_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 71 78 2b 76 4f 55 4c 36 35 42 } 		$a_01_1 = {4b 69 2d 6d 55 58 4b 34 53 } 		$a_01_2 = {71 51 66 32 6b 4f 66 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}