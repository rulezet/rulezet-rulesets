rule Trojan_Win64_CobaltStrike_AB_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 6f 41 ?? 48 8d 49 ?? 66 0f 6f ca 66 0f ef c8 f3 0f 7f 49 ?? f3 0f 6f 41 ?? 66 0f ef c2 f3 0f 7f 41 ?? f3 0f 6f 49 ?? 66 0f ef ca f3 0f 7f 49 ?? 66 0f 6f ca f3 0f 6f 41 ?? 66 0f ef c8 f3 0f 7f 49 ?? 49 83 ee } 		$a_03_1 = {41 8b c1 4d 8d 40 01 99 41 ff c1 f7 ff 48 63 c2 0f b6 4c 04 ?? 41 30 48 ff 49 83 ea 01 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}