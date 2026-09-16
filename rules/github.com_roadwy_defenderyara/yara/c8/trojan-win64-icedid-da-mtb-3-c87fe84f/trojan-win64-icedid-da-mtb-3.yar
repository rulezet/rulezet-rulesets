rule Trojan_Win64_IcedID_DA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b d0 c1 ea 10 2b c1 2b 83 ?? ?? ?? ?? 05 c3 e6 0b 00 89 83 ?? ?? ?? ?? 2b 4b 50 01 4b 30 48 63 4b 7c 48 8b 83 ?? ?? ?? ?? 88 14 01 41 8b d0 44 01 53 7c 48 63 4b 7c 48 8b 83 ?? ?? ?? ?? c1 ea 08 88 14 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}