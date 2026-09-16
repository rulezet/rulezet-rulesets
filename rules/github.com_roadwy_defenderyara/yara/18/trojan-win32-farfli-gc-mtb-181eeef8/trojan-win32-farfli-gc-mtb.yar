rule Trojan_Win32_Farfli_GC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 1c 32 89 55 ?? 8d 04 32 8b 45 ?? 03 c8 0f b6 04 37 0f b6 d3 03 c2 [0-30] 8a 04 32 30 01 ff 45 ?? 8b 45 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}