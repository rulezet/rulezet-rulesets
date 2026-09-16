rule Trojan_Win32_Ekstak_SM_MSR_2{
	meta:
		description = "Trojan:Win32/Ekstak.SM!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c3 03 c1 6a 00 6a 00 6a 00 8a 08 6a 00 32 ca 6a 00 88 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}