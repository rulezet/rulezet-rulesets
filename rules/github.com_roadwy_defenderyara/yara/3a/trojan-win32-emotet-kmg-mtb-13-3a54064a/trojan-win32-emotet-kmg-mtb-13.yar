rule Trojan_Win32_Emotet_KMG_MTB_13{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c3 99 bb c1 05 00 00 f7 fb 0f b6 04 0f 89 7c 24 18 8a 1c 0a 88 1c 0f 88 04 0a 0f b6 04 0f 89 54 24 1c 0f b6 14 0a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}