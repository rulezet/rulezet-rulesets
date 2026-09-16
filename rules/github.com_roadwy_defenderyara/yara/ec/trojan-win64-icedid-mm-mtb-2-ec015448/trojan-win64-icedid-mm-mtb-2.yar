rule Trojan_Win64_IcedID_MM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 c1 ea 1c 01 d0 83 e0 ?? 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 83 85 6c 0b 00 00 ?? 8b 85 6c 0b 00 00 3b 85 54 0b 00 00 7c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}