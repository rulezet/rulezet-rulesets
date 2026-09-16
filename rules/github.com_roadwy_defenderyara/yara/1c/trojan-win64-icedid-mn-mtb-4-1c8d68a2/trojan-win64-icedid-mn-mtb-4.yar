rule Trojan_Win64_IcedID_MN_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 ea 8d 04 0a 89 c2 c1 fa 05 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 2d 89 ca 29 c2 89 d0 48 98 48 03 85 88 02 00 00 0f b6 00 44 31 c8 41 88 00 83 85 9c 02 00 00 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}