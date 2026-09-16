rule Trojan_Win64_Cobaltstrike_KGF_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.KGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af 83 98 00 00 00 8b 83 60 01 00 00 ff c8 31 83 88 01 00 00 48 8b 83 f8 00 00 00 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 83 ac 00 00 00 48 63 8b ac 00 00 00 48 8b 83 f8 00 00 00 c1 ea 08 88 14 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}