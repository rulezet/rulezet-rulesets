rule Trojan_Win32_Emotet_PDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 30 55 } 		$a_81_1 = {6a 49 70 4f 73 4a 36 6b 75 32 58 41 71 59 70 4f 47 77 36 37 5a 78 44 35 68 6c 66 30 6b 41 57 6f 63 70 36 6d } 	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}