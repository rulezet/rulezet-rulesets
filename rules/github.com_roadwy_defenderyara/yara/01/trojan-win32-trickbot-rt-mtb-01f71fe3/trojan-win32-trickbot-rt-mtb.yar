rule Trojan_Win32_TrickBot_RT_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 80 c2 64 85 f6 76 ?? 8b 45 ?? 8a 08 32 ca 02 ca 88 08 40 4e 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}