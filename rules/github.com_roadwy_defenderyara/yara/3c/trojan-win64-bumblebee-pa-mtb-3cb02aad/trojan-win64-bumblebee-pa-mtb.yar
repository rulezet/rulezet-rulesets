rule Trojan_Win64_Bumblebee_PA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 81 b8 03 00 00 49 8b [0-02] 08 49 8b [0-02] 70 02 00 00 48 69 88 40 01 00 00 [0-04] 48 31 8a d0 03 00 00 4d 8b [0-02] 58 04 00 00 49 63 [0-02] 0c 06 00 00 49 63 [0-02] 08 06 00 00 41 8b 0c 80 41 31 0c 90 90 41 8b [0-02] 1c 06 00 00 23 ?? 7d } 		$a_01_1 = {4f 62 6f 58 62 51 58 4d 50 42 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}