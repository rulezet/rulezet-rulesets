rule Trojan_Win32_Amadey_AY_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 43 ca 03 c1 3b f0 74 ?? 8a 0c 33 32 0e 8b 57 10 8b 5f 14 88 4d fc 3b d3 73 ?? 8d 42 01 89 47 10 8b c7 83 fb 10 72 ?? 8b 07 8b 5d ec 46 88 0c 10 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}