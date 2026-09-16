rule Trojan_Win32_Dridex_DE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 4c 24 50 83 f8 6a 89 44 24 24 0f 84 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 44 24 30 8d 65 fc 5e 5d c3 a1 ?? ?? ?? ?? 0f b6 00 3d b8 00 00 00 0f 84 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}