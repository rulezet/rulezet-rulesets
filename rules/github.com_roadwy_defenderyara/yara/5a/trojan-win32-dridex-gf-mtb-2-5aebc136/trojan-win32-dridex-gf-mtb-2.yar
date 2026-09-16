rule Trojan_Win32_Dridex_GF_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 0c 05 c8 50 04 01 83 44 24 ?? 04 a3 ?? ?? ?? ?? 89 02 8b 15 ?? ?? ?? ?? 2b 54 24 ?? 8b 44 24 ?? 81 c2 14 82 01 00 83 6c 24 ?? 01 89 15 ?? ?? ?? ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}