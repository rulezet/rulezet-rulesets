rule Trojan_Win32_Ekstak_CCIQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 18 53 56 57 e8 ?? ?? de ff 89 45 fc e9 ?? ?? ?? ff 20 10 00 00 00 00 00 00 00 43 56 20 20 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}