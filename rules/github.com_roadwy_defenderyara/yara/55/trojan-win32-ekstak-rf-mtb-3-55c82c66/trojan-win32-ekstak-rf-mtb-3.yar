rule Trojan_Win32_Ekstak_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 53 56 57 e8 75 ff ff ff 0f be d8 b9 41 00 00 00 33 c0 bf 54 f7 4c 00 f3 ab e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}