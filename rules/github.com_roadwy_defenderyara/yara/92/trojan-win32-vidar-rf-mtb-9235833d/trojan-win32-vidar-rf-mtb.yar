rule Trojan_Win32_Vidar_RF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 31 bf ?? ?? ?? ?? 2b de 2b f9 eb 03 8d 49 00 8a 04 13 8d 52 01 34 ?? 88 42 ff 4f 75 f2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}