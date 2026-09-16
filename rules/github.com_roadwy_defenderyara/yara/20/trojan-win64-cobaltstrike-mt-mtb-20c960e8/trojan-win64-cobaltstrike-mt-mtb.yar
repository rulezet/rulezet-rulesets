rule Trojan_Win64_Cobaltstrike_MT_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 28 48 89 38 48 8b 44 24 40 48 89 44 24 30 b9 01 00 00 00 ff d3 48 89 44 24 38 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}