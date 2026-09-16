rule Trojan_Win32_QakBot_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 50 46 30 0c 54 64 72 68 79 6d 77 34 6f 69 35 6a 0b 64 72 68 79 6d 77 34 6f 69 35 6a 04 4c 65 66 74 03 50 01 03 54 6f 70 03 87 00 05 57 69 64 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}