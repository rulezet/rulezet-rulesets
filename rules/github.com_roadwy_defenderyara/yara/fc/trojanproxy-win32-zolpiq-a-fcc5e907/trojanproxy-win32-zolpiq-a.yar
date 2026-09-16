rule TrojanProxy_Win32_Zolpiq_A{
	meta:
		description = "TrojanProxy:Win32/Zolpiq.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 73 69 6d 61 67 65 2e 64 61 74 } 		$a_01_1 = {68 3f 00 0f 00 56 56 ff d0 3b c6 75 04 33 c0 5e c3 68 ff 01 0f 00 ff 74 24 0c 50 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}