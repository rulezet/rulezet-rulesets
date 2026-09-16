rule Trojan_Win32_Ekstak_RZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 18 53 56 57 89 65 e8 9b 33 d2 89 55 fc e9 ?? ?? ?? ?? 20 10 00 00 00 00 00 00 00 43 56 20 20 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}