rule Trojan_Win32_RedLine_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2c ce 50 b8 ff 56 00 00 b8 52 2e 00 00 58 51 59 90 88 04 0b 52 52 5a ba 4f 75 00 00 52 eb 05 6e 92 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}