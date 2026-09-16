rule Trojan_Win32_Emotet_MB_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.MB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b d2 65 0f b6 c9 03 d1 8a 48 01 40 84 c9 75 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}