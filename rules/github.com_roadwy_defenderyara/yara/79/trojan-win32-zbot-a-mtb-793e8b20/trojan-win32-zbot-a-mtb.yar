rule Trojan_Win32_Zbot_A_MTB{
	meta:
		description = "Trojan:Win32/Zbot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 c1 da 05 33 dd 33 ff bf 2a 23 39 8c ff 75 bc c1 ca 0a b9 fe 4e f7 e0 c1 de 03 ff 15 6c d1 40 00 83 c4 04 c1 c2 01 89 d9 bb b6 54 1e 34 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}