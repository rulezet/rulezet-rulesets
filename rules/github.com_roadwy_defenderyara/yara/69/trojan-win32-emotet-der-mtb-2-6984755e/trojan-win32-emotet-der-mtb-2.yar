rule Trojan_Win32_Emotet_DER_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.DER!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 44 8b c7 2b c1 2b c6 03 54 24 40 8d 04 82 8b 54 24 4c 03 c3 8a 04 10 30 45 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}