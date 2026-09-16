rule Trojan_Win32_Vidar_AMAJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}