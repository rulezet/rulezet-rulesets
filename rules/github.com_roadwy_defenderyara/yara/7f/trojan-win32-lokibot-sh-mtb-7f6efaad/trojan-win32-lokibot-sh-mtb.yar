rule Trojan_Win32_Lokibot_SH_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec eb ?? 90 05 10 01 90 8a 45 08 90 05 10 01 90 30 01 90 05 10 01 90 eb ?? 90 05 10 01 90 8b 4d 0c 90 05 10 01 90 eb ?? 90 05 10 01 90 5d c2 } 		$a_03_1 = {8b ca 03 cb c6 01 ?? 90 05 10 01 90 43 48 75 ?? 33 c0 5b c3 } 		$a_03_2 = {8b da 03 d9 90 05 10 01 90 c6 03 ?? 41 48 75 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}