rule Trojan_Win32_Trickbot_PI_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.PI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 00 75 00 63 00 6b 00 20 00 53 00 6f 00 70 00 68 00 6f 00 73 00 } 		$a_01_1 = {5c 43 75 73 74 6f 6d 54 6f 6f 6c 54 69 70 50 6c 75 73 44 65 6d 6f 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}