rule Trojan_Win32_Strab_RF_MTB{
	meta:
		description = "Trojan:Win32/Strab.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f2 4e 88 95 37 ff ff ff 0f b7 05 ?? ?? ?? ?? 99 05 5b 0f d8 99 81 d2 54 73 0e 00 a3 ?? ?? ?? ?? 8b 45 c0 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}