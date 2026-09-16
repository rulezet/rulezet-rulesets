rule PWS_Win32_Fareit_MTB_2{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 d9 04 0f 8d ?? ?? ff ff 90 0a 00 02 89 1c 08 90 0a 00 02 81 f3 90 0a 00 02 8b 1c 0a } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}