rule Trojan_Win32_Emotet_SQ_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SQ!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b c7 33 d2 83 c4 04 f7 f1 8a 04 1f 8a 54 55 00 32 c2 88 04 1f 8b 44 24 1c 47 3b f8 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}