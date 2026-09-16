rule Trojan_Win64_IcedID_DR_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DR!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 78 8b c7 41 0f af c8 2b c1 44 0f af c0 8b 4d 78 8b 85 80 00 00 00 03 c8 b8 56 55 55 55 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}