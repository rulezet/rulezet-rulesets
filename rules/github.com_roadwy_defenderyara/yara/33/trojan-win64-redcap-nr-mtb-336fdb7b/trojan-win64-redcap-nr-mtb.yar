rule Trojan_Win64_Redcap_NR_MTB{
	meta:
		description = "Trojan:Win64/Redcap.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 3d 78 5e 0a 00 44 8b 0f 45 85 c9 0f 85 ac 02 00 00 65 48 8b 04 25 ?? ?? ?? ?? 48 8b 1d ac 5d 0a 00 48 8b 70 08 31 ed } 		$a_03_1 = {75 e2 48 8b 35 ?? ?? ?? ?? 31 ed 8b 06 83 f8 ?? 0f 84 13 02 00 00 8b 06 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}