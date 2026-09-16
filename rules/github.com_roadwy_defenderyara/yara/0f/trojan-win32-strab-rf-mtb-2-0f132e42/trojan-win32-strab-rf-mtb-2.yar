rule Trojan_Win32_Strab_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Strab.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8b 45 fc 33 d0 89 55 fc 8b 55 fc 8b f3 85 d2 74 03 8b 75 fc 8b 45 fc 99 f7 fe 8b 55 fc bf 05 00 00 00 0f af c2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}