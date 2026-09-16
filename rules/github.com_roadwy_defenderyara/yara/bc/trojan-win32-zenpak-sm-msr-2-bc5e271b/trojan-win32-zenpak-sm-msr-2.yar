rule Trojan_Win32_Zenpak_SM_MSR_2{
	meta:
		description = "Trojan:Win32/Zenpak.SM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {28 8b 15 f8 ?? ?? 02 8a 94 0a f8 94 08 00 8b 3d 3c ?? ?? 00 88 14 0f 3d 03 02 00 00 } 		$a_00_1 = {46 00 49 00 5a 00 45 00 5a 00 55 00 42 00 41 00 52 00 45 00 46 00 4f 00 47 00 55 00 44 00 55 00 53 00 49 00 53 00 45 00 4c 00 49 00 5a 00 49 00 4d 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}