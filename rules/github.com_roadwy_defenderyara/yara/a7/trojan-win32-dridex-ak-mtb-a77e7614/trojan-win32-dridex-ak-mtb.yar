rule Trojan_Win32_Dridex_AK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 33 f4 8b 44 24 1c c6 44 24 33 36 66 8b 4c 24 0e 66 0f af c9 8a 50 01 66 89 4c 24 42 0f b6 c2 66 c7 44 24 42 77 c7 83 f8 25 0f 84 d0 fe ff ff e9 74 fe ff ff } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}