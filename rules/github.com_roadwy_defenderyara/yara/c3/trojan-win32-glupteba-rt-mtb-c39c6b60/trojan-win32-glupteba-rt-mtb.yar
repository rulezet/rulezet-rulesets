rule Trojan_Win32_Glupteba_RT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 38 81 c0 04 00 00 00 89 d9 43 39 d0 75 ?? 09 f1 09 de c3 83 ec 04 ?? ?? ?? 2d 8b f0 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}