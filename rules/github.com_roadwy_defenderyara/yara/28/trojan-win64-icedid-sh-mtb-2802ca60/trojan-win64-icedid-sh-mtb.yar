rule Trojan_Win64_IcedID_SH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 10 66 01 da c1 ca 03 89 55 10 30 10 40 c1 ca 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}