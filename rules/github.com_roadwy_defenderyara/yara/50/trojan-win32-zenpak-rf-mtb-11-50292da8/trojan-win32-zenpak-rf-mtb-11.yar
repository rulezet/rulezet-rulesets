rule Trojan_Win32_Zenpak_RF_MTB_11{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c2 ba 0a 00 00 00 31 25 ?? ?? ?? ?? 29 c2 4a 01 d0 b9 02 00 00 00 e2 21 01 d0 89 f8 50 8f 05 ?? ?? ?? ?? ba 04 00 00 00 b8 05 00 00 00 31 1d ?? ?? ?? ?? e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}