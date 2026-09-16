rule Trojan_Win32_ClipBanker_JB_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.JB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 54 59 41 74 43 46 54 58 43 36 6f 44 77 42 33 69 79 4c 35 76 78 6e 46 57 71 47 74 77 50 59 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}