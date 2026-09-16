rule Trojan_Win64_Barys_MK_MTB{
	meta:
		description = "Trojan:Win64/Barys.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 8d 42 01 44 0f b6 d0 42 0f b6 4c 15 40 49 8d 04 09 44 0f b6 c8 42 0f b6 44 0d 40 42 88 44 15 40 42 88 4c 0d 40 42 0f b6 44 15 40 48 03 c1 0f b6 c0 0f b6 4c 05 40 41 30 0c 10 48 ff c2 49 3b d6 } 		$a_01_1 = {5c 61 63 63 65 73 73 5f 74 6f 6b 65 6e 2e 74 78 74 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}