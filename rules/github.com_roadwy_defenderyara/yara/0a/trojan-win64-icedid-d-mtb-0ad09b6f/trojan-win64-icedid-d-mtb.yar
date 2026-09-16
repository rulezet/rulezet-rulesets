rule Trojan_Win64_IcedID_D_MTB{
	meta:
		description = "Trojan:Win64/IcedID.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 c3 41 81 c3 18 8b e0 c1 41 83 eb 01 41 81 eb 18 8b e0 c1 41 0f af c3 83 e0 01 83 f8 00 0f 94 c3 80 e3 01 88 5d 02 41 83 fa 0a 0f 9c c3 80 e3 01 88 5d 03 c7 45 fc b6 ea 64 b3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}