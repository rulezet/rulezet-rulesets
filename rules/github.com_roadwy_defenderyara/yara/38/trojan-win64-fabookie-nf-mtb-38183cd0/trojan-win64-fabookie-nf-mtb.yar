rule Trojan_Win64_Fabookie_NF_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 a4 0a 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 10 eb 06 48 63 c3 } 		$a_01_1 = {4a 30 73 78 4a 38 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}