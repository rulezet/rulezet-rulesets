rule Trojan_Win32_Convagent_KK_MTB{
	meta:
		description = "Trojan:Win32/Convagent.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 85 c0 0f 84 ?? ?? 00 00 0f 10 05 ?? ?? 03 00 0f 11 40 1a 0f 10 05 ?? ?? 03 00 0f 11 40 10 0f 10 05 ?? ?? 03 00 48 89 85 ?? 05 00 00 0f 11 00 48 8d 4d } 		$a_01_1 = {46 72 65 65 6c 61 6e 63 65 72 5f 43 6f 6e 74 72 61 63 74 5f 56 69 65 77 65 72 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}