rule Trojan_Win32_TrickBot_DB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 cb 03 ce 81 e1 ff 00 00 80 88 1d ?? ?? ?? ?? 79 ?? 49 81 c9 00 ff ff ff 41 8a 89 ?? ?? ?? ?? 30 0c 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}