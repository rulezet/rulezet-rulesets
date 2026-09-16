rule Trojan_Win32_Zbot_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 dd 08 c6 45 de 2b c6 45 df 08 c6 45 e0 5c c6 45 e1 08 c6 45 e2 31 c6 45 e3 08 c6 45 e4 5c c6 45 e5 08 c6 45 e6 52 c6 45 e7 08 c6 45 e8 31 c6 45 e9 08 c6 45 ea 3f c6 45 eb 08 c6 45 ec 31 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}