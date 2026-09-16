rule Trojan_Win32_Ekstak_RF_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 53 56 57 b9 41 00 00 00 33 c0 bf 24 d4 4c 00 f3 ab } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}