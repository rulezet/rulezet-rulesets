rule Trojan_Win32_Emotet_KMG_MTB_11{
	meta:
		description = "Trojan:Win32/Emotet.KMG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 fd 33 c0 8a 04 3e 0f be 0c 0a 03 d9 b9 c3 10 00 00 03 c3 99 f7 f9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}