rule Trojan_Win32_Emotet_CP_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.CP!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 3c 8b 6c 24 20 03 d6 8a 04 02 30 45 00 ff 44 24 10 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}