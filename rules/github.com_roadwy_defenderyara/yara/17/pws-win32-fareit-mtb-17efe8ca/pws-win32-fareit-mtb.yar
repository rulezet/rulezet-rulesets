rule PWS_Win32_Fareit_MTB{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 8b 1c 0a 81 f3 ?? ?? ?? ?? 89 1c 08 f8 83 c1 04 81 f9 ?? ?? ?? ?? 75 ?? ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}