rule Trojan_Win32_Glupteba_RPD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 ff 74 01 ea 31 39 ?? ?? ?? ?? 81 c1 04 00 00 00 39 d1 75 eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}