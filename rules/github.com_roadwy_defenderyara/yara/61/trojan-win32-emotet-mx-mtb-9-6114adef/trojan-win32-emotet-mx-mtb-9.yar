rule Trojan_Win32_Emotet_MX_MTB_9{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 44 24 ?? 83 c0 01 89 44 24 ?? 8a 54 14 ?? 30 50 ff 39 ac 24 ?? ?? ?? ?? 0f 85 } 		$a_80_1 = {4f 4e 35 44 42 70 6e 6f 58 72 61 52 50 63 4c 66 48 7a 63 32 6c 38 45 42 72 44 4c 76 74 50 7a 34 53 6a } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}