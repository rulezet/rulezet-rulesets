rule Trojan_BAT_Taskun_SO_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 08 91 07 28 2c 00 00 06 0d 09 2c 0f 00 06 08 8f 6f 00 00 01 28 2d 00 00 06 00 00 04 06 08 91 6f bf 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 13 04 11 04 2d ca } 		$a_81_1 = {57 69 6e 64 6f 77 42 6c 69 6e 64 73 43 6c 69 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}