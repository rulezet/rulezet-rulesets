rule Trojan_Win32_CobaltStrike_GJK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca c1 ea ?? 89 d0 f7 e3 89 c8 6b d2 1c 29 d0 0f b6 84 05 ?? ?? ?? ?? 30 04 0e 83 c1 01 81 f9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}