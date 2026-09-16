rule Trojan_Win64_IcedID_EA_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 62 6b 73 61 6a 6e 61 68 62 73 66 6a 61 6b 73 66 6e 68 62 61 6b 73 66 } 		$a_01_1 = {75 72 68 6a 62 74 6e 65 6b 73 75 62 61 73 68 64 61 6a 6b 73 64 61 73 } 		$a_01_2 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}