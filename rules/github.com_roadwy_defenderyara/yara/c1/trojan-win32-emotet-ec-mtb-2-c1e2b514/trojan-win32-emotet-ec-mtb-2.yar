rule Trojan_Win32_Emotet_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 5c 5b 07 0f af da 8b d7 2b d0 03 d2 03 d2 2b d3 8b 5c 24 1c 0f af de 03 d6 8d 54 95 00 8d 1c 5b 03 db 03 db bd 10 00 00 00 2b eb 8b 5c 24 10 0f af e9 03 d5 03 53 20 } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}