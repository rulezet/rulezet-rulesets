rule Trojan_Win32_Glupteba_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 1e 01 f9 89 c9 46 81 c1 ?? ?? ?? ?? 57 5f 39 d6 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}