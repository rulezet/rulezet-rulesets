rule Trojan_Win64_IcedID_EA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 4c 24 20 4c 89 44 24 18 eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb ?? 80 44 24 ?? ?? c6 44 24 ?? ?? eb } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}