rule Trojan_Win64_IcedID_DM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 28 8a 4d 30 33 c8 66 0f 6e c7 88 4d 28 89 5d 20 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}