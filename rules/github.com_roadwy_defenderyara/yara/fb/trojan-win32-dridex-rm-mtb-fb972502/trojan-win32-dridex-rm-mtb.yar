rule Trojan_Win32_Dridex_RM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ca 81 c2 01 00 00 00 66 8b 75 8e 66 89 c7 66 31 fe 66 89 75 8e 89 95 44 ff ff ff 8a 19 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}