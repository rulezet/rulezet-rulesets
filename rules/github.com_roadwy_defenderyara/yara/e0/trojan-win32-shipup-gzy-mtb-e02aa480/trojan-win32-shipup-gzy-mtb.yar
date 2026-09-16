rule Trojan_Win32_ShipUp_GZY_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 00 00 68 ae 0c 02 00 6a 00 } 		$a_03_1 = {1e 32 00 40 c6 05 ?? ?? ?? ?? ?? 0b dd f3 7e } 		$a_80_2 = {62 66 70 65 6d 76 68 75 2e 76 63 64 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}