rule Trojan_Win64_Rhadamanthys_NR_MTB_2{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 d1 e0 48 85 c0 0f 85 9b 00 00 00 31 c0 86 05 f5 3e 0a 00 3c 02 74 7e 83 bd ?? 00 00 00 01 0f 85 a6 fd ff ff 4c 8b b5 ?? 00 00 00 0f b6 95 00 01 00 00 f6 c2 01 } 		$a_01_1 = {f6 c2 01 0f 85 82 fd ff ff 48 8b 05 26 3f 0a 00 48 8b 00 48 d1 e0 48 85 c0 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}