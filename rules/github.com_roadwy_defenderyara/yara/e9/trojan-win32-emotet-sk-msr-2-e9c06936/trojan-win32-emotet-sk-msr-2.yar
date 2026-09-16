rule Trojan_Win32_Emotet_SK_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SK!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 88 18 8b 5d f8 88 14 33 0f b6 00 0f b6 d2 03 c2 33 d2 f7 f1 8b 4d f0 8a 04 32 32 04 39 88 07 47 ff 4d 0c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}