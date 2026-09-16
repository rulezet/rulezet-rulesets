rule Trojan_Win32_Trickbot_KMG_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c0 ec 02 80 e4 0f 0a e1 8b 4c 24 ?? 88 64 24 ?? 88 44 24 ?? 88 47 ?? 0f b7 44 24 ?? 66 89 07 83 44 24 08 03 8b 44 24 ?? 40 e9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}