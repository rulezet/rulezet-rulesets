rule Trojan_Win32_Injuke_RC_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 f9 8b 45 dc 2b 50 14 8b 45 dc 8b 40 0c 0f b6 04 10 03 c6 99 b9 00 01 00 00 f7 f9 89 55 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}