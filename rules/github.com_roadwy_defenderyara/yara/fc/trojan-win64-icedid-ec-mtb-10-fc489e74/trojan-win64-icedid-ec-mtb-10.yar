rule Trojan_Win64_IcedID_EC_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af d1 44 31 f2 83 ca fe 44 39 f2 0f 94 c1 83 f8 0a 0f 9c c3 30 cb b9 ec 7d 1b 2b bd ec 7d 1b 2b 75 05 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}