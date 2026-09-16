rule Trojan_Win64_IcedID_ML_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.ML!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b 06 83 c0 1e 48 98 0f b7 4c 45 00 48 81 c1 6f 04 00 00 4b 31 0c c7 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}