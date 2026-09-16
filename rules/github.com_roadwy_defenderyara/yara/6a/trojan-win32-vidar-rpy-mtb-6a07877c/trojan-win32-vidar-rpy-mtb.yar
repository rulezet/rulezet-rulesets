rule Trojan_Win32_Vidar_RPY_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 30 06 02 00 59 8d 85 30 f7 ff ff 50 e8 23 06 02 00 59 8d 85 30 f7 ff ff 50 e8 16 06 02 00 59 8d 85 30 f7 ff ff 50 e8 09 06 02 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}