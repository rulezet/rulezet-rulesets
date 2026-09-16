rule Trojan_Win32_Lokibot_DECC_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.DECC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {33 71 b5 02 00 00 00 bc 29 40 00 cc 29 40 00 00 00 00 00 79 4f ad 33 99 66 cf 11 b7 } 		$a_81_1 = {61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}