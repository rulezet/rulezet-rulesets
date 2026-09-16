rule Trojan_Win32_Trickbot_AA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 3c 38 03 fe 50 8b c1 30 38 41 58 } 		$a_01_1 = {54 68 69 73 20 69 73 20 61 20 50 45 20 65 78 65 63 75 74 61 62 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}