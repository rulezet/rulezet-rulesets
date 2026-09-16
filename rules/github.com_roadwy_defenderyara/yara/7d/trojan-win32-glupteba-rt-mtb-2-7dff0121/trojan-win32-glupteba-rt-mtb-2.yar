rule Trojan_Win32_Glupteba_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 39 81 c6 bd fb 42 88 21 d8 81 c1 04 00 00 00 81 c6 01 00 00 00 39 d1 75 ?? bb 24 d1 40 86 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}