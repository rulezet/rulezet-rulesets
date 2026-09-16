rule Trojan_Win64_CobaltStrike_CB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c2 0f 57 ca f3 0f 7f 40 ?? f3 0f 6f 44 10 ?? f3 0f 7f 48 ?? 0f 57 c2 f3 0f 6f 4c 08 ?? f3 0f 7f 40 ?? 0f 57 ca f3 0f 7f 48 ?? 49 83 e9 01 75 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}