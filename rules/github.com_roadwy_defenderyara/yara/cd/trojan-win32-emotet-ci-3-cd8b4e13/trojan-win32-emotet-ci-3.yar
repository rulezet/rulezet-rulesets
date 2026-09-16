rule Trojan_Win32_Emotet_CI_3{
	meta:
		description = "Trojan:Win32/Emotet.CI,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 50 53 58 66 66 66 66 66 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}