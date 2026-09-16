rule Trojan_Win64_IcedID_FK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea ?? 48 8d 04 d2 48 03 c0 48 2b c8 48 2b cb 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 45 3b cd } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}