rule Trojan_Win32_Zusy_R_MTB{
	meta:
		description = "Trojan:Win32/Zusy.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 6b c0 2b 6b c0 3b 6b f0 27 8b 45 0c 8b 4d f0 0f be 14 08 31 f2 88 14 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}