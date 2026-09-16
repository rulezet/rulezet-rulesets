rule Trojan_BAT_PureLog_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/PureLog.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 44 20 4b 49 4c 4c 45 52 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_1 = {24 35 35 39 31 34 35 33 39 2d 31 62 39 30 2d 34 64 37 34 2d 39 36 64 30 2d 66 66 31 63 38 34 31 35 39 31 66 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}