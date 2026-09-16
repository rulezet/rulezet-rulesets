rule Trojan_BAT_PureLog_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/PureLog.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 44 69 71 54 47 6d 41 51 44 54 4d 39 36 58 36 58 79 2e 71 30 61 73 4a 79 6c 6d 70 62 56 64 46 68 5a 46 4c 58 } 		$a_01_1 = {71 6b 63 69 64 42 76 35 55 78 63 41 47 46 32 35 53 44 2e 32 33 63 51 66 31 59 67 62 46 77 4a 69 72 75 50 45 4a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}