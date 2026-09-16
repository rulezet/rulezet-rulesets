rule Trojan_Win32_Zbot_RI_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 44 fa e1 99 e2 c5 c5 75 bf e6 0f 3d 7e 9f 75 e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}