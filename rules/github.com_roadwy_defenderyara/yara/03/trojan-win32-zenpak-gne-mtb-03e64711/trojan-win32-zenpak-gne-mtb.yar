rule Trojan_Win32_Zenpak_GNE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 6c 98 55 89 75 ?? b8 ?? ?? ?? ?? 01 45 ?? 8b 45 ?? 8a 04 08 88 04 39 41 3b 0d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}