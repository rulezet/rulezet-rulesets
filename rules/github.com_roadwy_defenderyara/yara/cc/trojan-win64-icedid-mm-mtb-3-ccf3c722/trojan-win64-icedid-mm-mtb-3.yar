rule Trojan_Win64_IcedID_MM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ea 89 c8 c1 f8 ?? c1 fa 04 29 c2 89 c8 0f af d5 29 d0 48 63 d0 41 0f b6 14 10 41 32 14 0b 41 88 14 09 48 83 c1 01 48 81 f9 ?? ?? ?? ?? 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}