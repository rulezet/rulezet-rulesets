rule Trojan_Win32_Zbot_C_MTB{
	meta:
		description = "Trojan:Win32/Zbot.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b fb f3 a5 2d dc 07 00 00 04 3c 33 c9 66 a5 d0 e0 30 04 19 41 83 f9 7a 7c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}