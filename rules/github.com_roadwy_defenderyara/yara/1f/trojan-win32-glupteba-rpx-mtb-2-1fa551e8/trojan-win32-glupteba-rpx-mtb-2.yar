rule Trojan_Win32_Glupteba_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 01 f6 31 0f 47 39 df 75 ea c3 52 8b 34 24 83 c4 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}