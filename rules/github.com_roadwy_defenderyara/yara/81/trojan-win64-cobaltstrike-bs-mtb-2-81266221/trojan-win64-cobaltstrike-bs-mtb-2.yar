rule Trojan_Win64_CobaltStrike_BS_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 c0 39 c2 7e ?? 49 89 c1 41 83 e1 ?? 47 ?? ?? ?? 44 30 0c 01 48 ff c0 eb ?? 4c 8d 05 ?? ?? ?? ?? e9 } 		$a_00_1 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } 		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}