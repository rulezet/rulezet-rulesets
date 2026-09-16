rule Trojan_Win32_Ekstak_RF_MTB_9{
	meta:
		description = "Trojan:Win32/Ekstak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 32 e8 18 10 20 00 83 c4 04 8b 0d b4 fd 64 00 03 c8 89 0d b4 fd 64 00 e8 22 dd 16 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 98 fc 64 00 e8 3d 00 00 00 6a 00 6a 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}