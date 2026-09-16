rule Trojan_Win32_Zenpak_RF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 38 83 f2 07 83 f2 04 8d 05 ?? ?? ?? ?? 01 30 01 c2 83 c2 03 48 89 d8 50 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}