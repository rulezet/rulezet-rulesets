rule Trojan_Win64_CobaltStrike_YAD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4a 60 0f af c8 89 4a 60 8b 05 a5 63 04 00 48 8b 0d d6 63 04 00 41 31 04 0e 49 83 c6 04 44 8b 0d b7 63 04 00 4c 8b 05 f8 62 04 00 41 81 c1 5c 49 ed ff 8b 15 d3 63 04 00 44 03 ca } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}