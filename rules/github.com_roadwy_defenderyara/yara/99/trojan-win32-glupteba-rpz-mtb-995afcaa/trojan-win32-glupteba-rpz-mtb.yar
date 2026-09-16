rule Trojan_Win32_Glupteba_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 03 81 c3 04 00 00 00 39 f3 75 ef } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}