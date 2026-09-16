rule Trojan_Win64_Cobaltstrike_EN_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 cb 49 89 d2 31 c9 4c 39 c9 73 ?? 48 89 c8 31 d2 49 f7 f2 41 8a 04 13 41 30 04 08 48 8b 05 ?? ?? ?? ?? 48 c1 e0 04 48 8d 4c 01 01 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}