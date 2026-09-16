rule Trojan_Win64_Lazy_NLA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 75 31 1e 00 48 8b 01 48 05 ?? ?? ?? ?? 48 89 41 10 48 89 41 ?? e8 7f 43 00 00 48 8d 3d ?? ?? ?? ?? e8 f3 41 00 00 48 8b 1d 24 66 23 00 } 		$a_01_1 = {4e 5a 52 42 2e 78 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}