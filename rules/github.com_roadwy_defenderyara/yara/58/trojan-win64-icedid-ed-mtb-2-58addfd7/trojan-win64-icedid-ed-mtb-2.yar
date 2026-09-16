rule Trojan_Win64_IcedID_ED_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 61 72 65 74 64 6a 62 6b 61 73 76 64 61 6a 61 73 64 } 		$a_01_1 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}