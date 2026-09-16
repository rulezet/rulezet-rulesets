rule Trojan_Win64_IcedID_DG_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 c3 3f 8a 53 01 8a 0b 8a 43 ff 48 8d 5b 03 c0 e2 03 80 e1 07 0a d1 24 07 c0 e2 03 0a d0 43 88 14 08 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}