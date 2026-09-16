rule Trojan_Win32_RedLineStealer_PC_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 c7 45 fc ?? ?? ?? ?? 8b 45 0c 01 45 fc 83 6d fc ?? 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}