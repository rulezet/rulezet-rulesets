rule Trojan_Win32_Redline_MP_MTB{
	meta:
		description = "Trojan:Win32/Redline.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 10 90 01 45 fc 8b 45 08 8b 4d fc 89 08 c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}