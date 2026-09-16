rule Trojan_Win32_Glupteba_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4f 57 8b 34 24 83 c4 04 31 0b 43 81 ee ?? ?? ?? ?? 01 f6 39 d3 75 df 56 5f 47 c3 8d 0c 01 81 c7 01 00 00 00 8b 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}