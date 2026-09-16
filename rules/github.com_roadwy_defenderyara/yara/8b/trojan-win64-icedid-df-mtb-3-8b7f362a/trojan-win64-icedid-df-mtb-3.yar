rule Trojan_Win64_IcedID_DF_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DF!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 8c 20 35 69 45 9a 36 89 44 8c 20 48 ff c1 48 83 f9 04 72 ea } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}