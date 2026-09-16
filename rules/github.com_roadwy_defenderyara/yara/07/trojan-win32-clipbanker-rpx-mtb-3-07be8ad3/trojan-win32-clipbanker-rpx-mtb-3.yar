rule Trojan_Win32_ClipBanker_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 16 3b e3 8d b6 02 00 00 00 81 c9 ?? ?? ?? ?? d3 f0 0f b6 4c 25 00 66 d3 f8 8d ad 01 00 00 00 66 0f b3 e8 32 cb 9f fe c1 0f bd c2 f6 d9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}