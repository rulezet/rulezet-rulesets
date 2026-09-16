rule Trojan_Win64_FileCoder_NF_MTB_2{
	meta:
		description = "Trojan:Win64/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 41 3b 11 41 8d 40 01 0f b7 51 02 41 0f 44 c0 48 83 c1 02 49 83 c1 02 44 8b c0 66 83 fa 3d 75 df } 		$a_01_1 = {49 8b 0a 45 8b c7 66 83 39 2d } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}