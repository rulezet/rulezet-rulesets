rule Trojan_Win32_NSISInject_RH_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 89 45 b0 8b 45 10 68 00 00 00 80 50 ff 15 ?? ?? ?? ?? 8b f0 6a 00 56 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}