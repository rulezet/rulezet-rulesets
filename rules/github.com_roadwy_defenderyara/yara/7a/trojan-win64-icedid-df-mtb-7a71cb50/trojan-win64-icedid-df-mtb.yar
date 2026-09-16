rule Trojan_Win64_IcedID_DF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 04 0a e9 ?? ?? ?? ?? eb ?? f7 7c 24 ?? 8b c2 66 3b c0 74 ?? 33 c1 48 63 4c 24 ?? 3a ff 74 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}