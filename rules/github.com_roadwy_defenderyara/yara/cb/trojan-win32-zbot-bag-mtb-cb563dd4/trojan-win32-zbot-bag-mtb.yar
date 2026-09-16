rule Trojan_Win32_Zbot_BAG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c6 fe 83 ee ff 29 de 89 f3 6a 00 8f 01 01 31 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}