rule Trojan_Win64_IcedID_QM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.QM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 48 b9 0a 01 00 00 2b c8 8b 45 48 2b c8 41 03 cc 89 4d 48 8a 45 50 88 02 44 89 4d 48 44 89 55 50 8b 45 48 41 23 c6 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}