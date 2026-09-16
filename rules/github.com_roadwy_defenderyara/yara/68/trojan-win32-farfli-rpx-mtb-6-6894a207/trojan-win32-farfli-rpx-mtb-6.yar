rule Trojan_Win32_Farfli_RPX_MTB_6{
	meta:
		description = "Trojan:Win32/Farfli.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 53 53 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 5f 85 f6 75 04 5e 5b 59 c3 } 		$a_01_1 = {68 64 69 65 74 72 69 63 68 32 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}