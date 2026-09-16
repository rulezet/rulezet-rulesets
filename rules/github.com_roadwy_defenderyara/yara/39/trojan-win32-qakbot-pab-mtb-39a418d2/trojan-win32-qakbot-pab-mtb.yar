rule Trojan_Win32_Qakbot_PAB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 3a c0 90 13 bb 04 00 00 00 53 3a ed 90 13 5e f7 f6 66 3b db 90 13 0f b6 44 15 ?? 33 c8 3a c0 90 13 8b 45 ?? 88 4c 05 ?? 90 13 8b 45 ?? 40 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}