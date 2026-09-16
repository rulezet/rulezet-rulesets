rule Trojan_Win32_Meterpreter_RPX_MTB{
	meta:
		description = "Trojan:Win32/Meterpreter.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f9 89 de 8a 06 30 07 47 66 81 3f ?? ?? 74 08 46 80 3e ?? 75 ee eb ea } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}