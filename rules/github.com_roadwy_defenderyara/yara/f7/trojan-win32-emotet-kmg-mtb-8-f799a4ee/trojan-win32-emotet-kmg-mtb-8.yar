rule Trojan_Win32_Emotet_KMG_MTB_8{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c6 be 7c 0d 00 00 99 f7 fe 33 c0 8a 04 39 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}