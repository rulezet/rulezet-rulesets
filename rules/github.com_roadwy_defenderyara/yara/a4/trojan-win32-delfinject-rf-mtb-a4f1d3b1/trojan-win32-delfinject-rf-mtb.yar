rule Trojan_Win32_DelfInject_RF_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 8b 00 25 ff ff 00 00 50 8b 06 50 e8 ?? ?? ?? ?? 89 07 eb } 		$a_03_1 = {83 c0 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 8b 06 50 e8 ?? ?? ?? ?? 89 07 8b 03 8b 17 89 10 83 03 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}