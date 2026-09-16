rule Trojan_Win32_Glupteba_RPH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 13 81 c3 04 00 00 00 39 cb 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}