rule Trojan_Win32_Injuke_RD_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 6b 8b 4d 08 03 4d fc 88 01 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}