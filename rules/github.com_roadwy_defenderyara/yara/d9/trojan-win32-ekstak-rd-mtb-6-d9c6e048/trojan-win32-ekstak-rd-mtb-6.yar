rule Trojan_Win32_Ekstak_RD_MTB_6{
	meta:
		description = "Trojan:Win32/Ekstak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 45 14 56 50 ff 15 30 94 46 00 3d ?? ?? ?? ?? 74 14 8b 35 f0 97 46 00 6a 00 48 50 68 bb 00 00 00 ff 75 14 ff d6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}