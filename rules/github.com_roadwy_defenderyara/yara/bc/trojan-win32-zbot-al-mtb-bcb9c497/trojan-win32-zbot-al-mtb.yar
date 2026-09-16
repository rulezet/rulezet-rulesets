rule Trojan_Win32_Zbot_AL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 13 43 c1 ea 08 41 83 f9 04 75 0a ba 72 c6 0e de b9 00 00 00 00 81 fb 9f fa 40 00 72 } 	condition:
		((#a_01_0  & 1)*4) >=4
 
}