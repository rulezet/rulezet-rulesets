rule Trojan_Win64_Zusy_AH_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ca f7 da d3 ca b9 ?? ?? ?? ?? 44 29 c9 d3 c2 89 c1 d3 ca 81 f2 ?? ?? ?? ?? 0f ca d3 ca } 		$a_01_1 = {f7 d0 d3 c8 48 63 c8 8b 44 8d 00 0f c8 ff c9 d3 c8 f7 d0 d3 c8 ff c0 } 	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}