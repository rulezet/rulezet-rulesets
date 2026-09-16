rule Trojan_Win32_Dridex_GF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c7 d4 e0 08 01 89 3d ?? ?? ?? ?? 89 bc 2e ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 66 8b 0d ?? ?? ?? ?? 8a c2 02 c1 83 c6 04 2c ?? 81 fe 33 1c 00 00 0f 82 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}