rule Trojan_Win32_Convagent_BAF_MTB_3{
	meta:
		description = "Trojan:Win32/Convagent.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 77 50 6a 00 ff 15 ?? ?? ?? ?? 8b d0 89 55 fc 85 d2 0f 84 ?? ?? ?? ?? 0f b7 4f 06 56 0f b7 77 14 83 c6 18 8d 04 89 03 f7 c1 e0 03 2b c3 03 c6 50 53 52 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}