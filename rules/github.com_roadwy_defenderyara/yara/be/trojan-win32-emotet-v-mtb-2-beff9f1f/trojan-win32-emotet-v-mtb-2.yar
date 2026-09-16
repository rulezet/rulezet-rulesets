rule Trojan_Win32_Emotet_V_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.V!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 8c 0c 8b f2 8b 54 b4 0c 89 54 8c 0c 0f b6 d0 89 54 b4 0c 8b 44 8c 0c 03 c2 99 f7 fd 0f b6 44 94 0c 30 44 1f ff 3b bc 24 94 07 00 00 72 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}