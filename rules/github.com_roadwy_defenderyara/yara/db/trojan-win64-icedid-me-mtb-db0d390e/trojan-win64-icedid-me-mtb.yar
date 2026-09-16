rule Trojan_Win64_IcedID_ME_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 48 b9 ?? ?? ?? ?? 2b c8 8b 45 48 2b c8 83 c1 1c 89 4d 48 8a 45 50 88 02 44 89 65 48 44 89 6d 50 8b 45 48 23 c6 7d } 		$a_01_1 = {44 6c 6c 4d 61 69 6e } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}