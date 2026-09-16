rule Trojan_Win32_Dridex_EN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 00 02 01 0b 01 00 00 00 40 03 00 } 		$a_01_1 = {03 0c 60 2a 00 07 4a 10 01 03 01 00 04 00 10 00 01 00 0c 00 02 01 0a 8c 01 70 01 00 00 07 0b 27 0e 12 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}