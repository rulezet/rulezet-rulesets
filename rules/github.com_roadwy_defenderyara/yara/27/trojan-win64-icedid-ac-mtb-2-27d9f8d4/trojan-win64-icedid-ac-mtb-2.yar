rule Trojan_Win64_IcedID_AC_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 38 0f b6 00 0f b6 4c 24 40 33 c1 48 8b 4c 24 60 48 8b 54 24 38 48 2b d1 48 8b ca 0f b6 c9 83 e1 08 33 c1 48 8b 4c 24 38 88 01 48 63 44 24 20 48 8b 4c 24 38 48 03 c8 48 8b c1 48 89 44 24 38 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}