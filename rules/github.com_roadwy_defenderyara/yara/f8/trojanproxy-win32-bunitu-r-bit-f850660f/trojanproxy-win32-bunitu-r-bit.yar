rule TrojanProxy_Win32_Bunitu_R_bit{
	meta:
		description = "TrojanProxy:Win32/Bunitu.R!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 74 6e 76 69 61 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 61 74 6e 76 69 61 } 		$a_03_1 = {89 4a 04 83 6a 04 ?? b8 01 00 00 00 48 b9 ?? ?? ?? ?? 41 } 		$a_03_2 = {fe 09 c6 41 ?? ?? fe 49 ?? c6 41 ?? ?? fe 49 ?? fe 09 51 e8 68 20 00 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}