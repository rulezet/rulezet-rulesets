rule Trojan_Win32_Razy_RPY_MTB{
	meta:
		description = "Trojan:Win32/Razy.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 06 81 c1 8a 91 ac 6f 81 c6 04 00 00 00 39 d6 75 e9 c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}