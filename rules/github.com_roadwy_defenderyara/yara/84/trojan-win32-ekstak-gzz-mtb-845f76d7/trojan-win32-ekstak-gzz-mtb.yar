rule Trojan_Win32_Ekstak_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {41 4a 41 58 20 44 48 54 4d 4c 20 54 72 61 63 6b 69 6e 67 } 	condition:
		((#a_80_0  & 1)*1) >=1
 
}