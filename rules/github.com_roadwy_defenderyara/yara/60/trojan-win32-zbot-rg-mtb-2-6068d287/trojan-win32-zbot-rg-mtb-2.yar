rule Trojan_Win32_Zbot_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 ea 03 8b c8 83 c0 08 83 e1 07 89 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 14 2a d3 ea 8b ce 23 d3 8b ea d3 e5 8d 0c 3e } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}