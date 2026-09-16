rule Trojan_Win64_IcedID_EB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 48 8d 49 01 83 e0 07 ff c2 0f b6 44 30 10 30 41 ff } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}