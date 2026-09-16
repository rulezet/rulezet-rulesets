rule Trojan_Win32_Pernefed_3{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 03 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f0 b8 ?? ?? 50 00 e8 ?? ?? ef ff 68 ?? ?? 50 00 e8 ?? ?? ef ff 8b 15 ?? ?? 51 00 89 02 68 ?? ?? 50 00 6a 00 6a 00 e8 ?? ?? ef ff 85 c0 79 05 } 		$a_00_1 = {ff ff ff ff 10 00 00 00 46 6f 75 6e 64 20 74 68 72 65 61 74 73 3a 20 30 00 } 		$a_00_2 = {ff ff ff ff 15 00 00 00 53 74 61 74 75 73 3a 20 53 63 61 6e 6e 69 6e 67 20 66 69 6c 65 00 } 	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=102
 
}