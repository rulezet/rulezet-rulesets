rule Trojan_Win32_Vidar_MC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc c1 e0 04 8b 4d 08 0f be 09 03 c1 89 45 fc 8b 45 fc 25 00 00 00 f0 89 45 f4 74 11 8b 45 f4 c1 e8 18 33 45 fc 25 ff ff ff 0f 89 45 fc } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}