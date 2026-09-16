rule Trojan_Win64_Rozena_NM_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 e8 cf 07 ?? ?? 85 c0 74 21 65 48 8b 04 25 30 00 00 00 48 8b 48 08 eb ?? 48 3b c8 74 ?? 33 c0 f0 48 0f b1 0d 34 97 01 00 75 ?? 32 c0 48 83 } 		$a_03_1 = {40 53 48 83 ec 20 80 3d e4 96 01 00 00 8b d9 75 ?? 83 f9 01 77 ?? e8 45 07 00 00 85 c0 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}