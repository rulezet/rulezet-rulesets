rule Trojan_Win32_Glupteba_RPE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 ff 74 01 ea 31 19 ?? ?? ?? ?? 81 c1 04 00 00 00 47 39 c1 75 ea } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}