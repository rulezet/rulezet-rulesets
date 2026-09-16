rule Trojan_Win64_Lazy_NL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 85 ff 48 0f 44 f8 33 c0 48 83 ff e0 77 18 48 8b 0d ?? ?? ?? ?? 8d 50 08 4c 8b c7 } 		$a_03_1 = {75 b7 48 8b 1d ?? ?? ?? ?? 48 8b cb e8 c8 17 ff ff 48 83 25 9c 9e 0e 00 00 48 83 27 ?? c7 05 8a c6 0e 00 01 00 00 00 33 c0 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}