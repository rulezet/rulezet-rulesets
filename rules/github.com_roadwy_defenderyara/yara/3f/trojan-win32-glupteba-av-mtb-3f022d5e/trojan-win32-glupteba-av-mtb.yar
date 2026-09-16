rule Trojan_Win32_Glupteba_AV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 1e 83 ff 19 75 0b } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}