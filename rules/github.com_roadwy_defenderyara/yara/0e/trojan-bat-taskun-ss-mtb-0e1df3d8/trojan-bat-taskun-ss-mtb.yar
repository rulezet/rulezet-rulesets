rule Trojan_BAT_Taskun_SS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 03 11 07 11 08 91 6f c7 00 00 0a 00 00 11 08 17 58 13 08 11 08 11 04 fe 04 13 09 11 09 2d e0 } 		$a_01_1 = {57 6f 72 64 46 75 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}