rule Trojan_Win32_Emotet_KMG_MTB_15{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 1f 8a 0c 2b 88 0c 1f 47 81 ff 7c 0d 00 00 88 04 2b 0f 8c } 		$a_01_1 = {0f b6 04 2f 8a 14 2b 88 14 2f 83 c7 01 81 ff 7c 0d 00 00 88 04 2b 0f 8c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}