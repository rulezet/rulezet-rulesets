rule Trojan_Win32_CobaltStrike_PS_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 0f b6 0c 02 8b 45 fc 48 63 d0 48 8b 45 18 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 8b 45 fc 3b 45 20 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}