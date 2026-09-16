rule Trojan_Win64_IcedID_EB_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 67 61 67 69 68 73 66 67 79 75 6b 61 73 6a 68 67 79 6a 61 73 } 		$a_01_1 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}