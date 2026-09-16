rule Trojan_Win32_Vidar_PAN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 89 45 f0 8b c6 d3 e8 03 45 d0 89 45 f8 8b 45 f0 31 45 fc 8b 45 f8 31 45 fc 89 1d ?? ?? ?? ?? 8b 45 fc 29 45 f4 8d 45 e4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}