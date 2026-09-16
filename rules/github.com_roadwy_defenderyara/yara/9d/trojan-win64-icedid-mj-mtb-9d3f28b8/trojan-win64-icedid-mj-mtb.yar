rule Trojan_Win64_IcedID_MJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 2b c0 66 66 66 0f 1f 84 00 00 00 00 00 41 0f b6 0c 00 88 08 48 8d 40 01 83 ea 01 75 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}