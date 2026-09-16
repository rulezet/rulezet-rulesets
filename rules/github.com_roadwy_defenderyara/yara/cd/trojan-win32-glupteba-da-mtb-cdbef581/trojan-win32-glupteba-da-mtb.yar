rule Trojan_Win32_Glupteba_DA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 c1 e8 05 89 45 74 c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? fe ff ff 01 45 74 8b 55 74 33 d1 33 d3 8d 8d ?? fe ff ff 89 55 74 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}