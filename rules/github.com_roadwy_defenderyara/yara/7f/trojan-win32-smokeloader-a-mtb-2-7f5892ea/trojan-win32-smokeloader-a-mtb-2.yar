rule Trojan_Win32_SmokeLoader_A_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 47 86 c8 61 03 45 e4 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85 01 ff ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}