rule Trojan_Win32_Androm_BAR_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d0 52 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 16 83 c3 04 83 c6 04 3b 5d } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}