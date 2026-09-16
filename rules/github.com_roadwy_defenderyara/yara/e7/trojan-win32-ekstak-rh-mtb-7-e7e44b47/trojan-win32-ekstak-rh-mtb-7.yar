rule Trojan_Win32_Ekstak_RH_MTB_7{
	meta:
		description = "Trojan:Win32/Ekstak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 65 00 8d 55 f8 c7 45 f8 08 00 00 00 52 c7 45 fc 04 00 00 00 ff 15 ?? 30 65 00 c7 45 fc 00 00 00 00 ff 15 ?? 31 65 00 ff 15 ?? ?? 65 00 e9 } 		$a_01_1 = {44 00 69 00 73 00 6b 00 57 00 72 00 69 00 74 00 65 00 43 00 6f 00 70 00 79 00 5f 00 45 00 78 00 65 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}