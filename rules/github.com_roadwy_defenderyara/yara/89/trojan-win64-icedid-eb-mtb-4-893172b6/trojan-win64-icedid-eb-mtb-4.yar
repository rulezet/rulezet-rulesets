rule Trojan_Win64_IcedID_EB_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c2 41 8b cd 49 81 c8 1f 21 af 04 48 63 c2 48 81 f1 d2 3b 00 00 4c 89 83 00 02 00 00 48 3b c1 72 de } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}