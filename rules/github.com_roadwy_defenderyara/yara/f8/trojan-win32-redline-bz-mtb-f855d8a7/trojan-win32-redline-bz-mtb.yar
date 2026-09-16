rule Trojan_Win32_RedLine_BZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 01 8b 44 24 ?? 03 54 24 ?? 8b 0c b8 8b 44 24 ?? 8a 04 01 8d 4c ?? 24 30 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}