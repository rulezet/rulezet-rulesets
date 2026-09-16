rule Trojan_Win32_Emotet_SR_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SR!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 8b c8 8b 45 fc 33 d2 f7 f1 8b 45 08 8a 04 50 30 03 ff 45 fc 8b 45 fc 3b 45 10 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}