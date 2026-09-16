rule Trojan_Win32_ClipBanker_RPX_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 b9 82 00 00 00 99 f7 f9 81 c2 c8 00 00 00 52 ff 15 ?? ?? ?? ?? 33 c0 66 89 85 e8 bd ff ff 8d 85 e8 bd ff ff 50 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}