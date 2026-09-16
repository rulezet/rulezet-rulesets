rule Trojan_Win32_Emotet_KMG_MTB_9{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 3b 8a 11 83 c4 0c 88 14 3b 43 3b de 88 01 7c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}