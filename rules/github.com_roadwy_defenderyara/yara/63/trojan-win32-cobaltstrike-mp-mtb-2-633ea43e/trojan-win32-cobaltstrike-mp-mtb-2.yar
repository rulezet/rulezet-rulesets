rule Trojan_Win32_CobaltStrike_MP_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 6d fc 8a f1 88 4d ff 8a 48 fe 43 32 ca 88 48 0e 8a 48 ff 32 4d fe 88 48 0f 8a 08 32 cd 88 48 10 8a 48 01 32 ce 88 48 11 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}