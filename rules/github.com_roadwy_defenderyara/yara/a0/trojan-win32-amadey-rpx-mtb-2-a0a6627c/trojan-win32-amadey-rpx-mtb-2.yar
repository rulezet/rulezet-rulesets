rule Trojan_Win32_Amadey_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 30 33 c0 5e c2 04 00 56 8b 35 ?? ?? ?? ?? 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 ff d6 8b 35 ?? ?? ?? ?? 90 90 68 30 75 00 00 ff d6 eb f7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}