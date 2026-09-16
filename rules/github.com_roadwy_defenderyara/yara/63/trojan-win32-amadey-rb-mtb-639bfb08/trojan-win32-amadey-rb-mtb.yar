rule Trojan_Win32_Amadey_RB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 01 d0 88 08 8d 95 ec ?? fc ff 8b 45 f4 01 d0 0f b6 00 83 f0 49 89 c1 8d 95 ec ?? fc ff 8b 45 f4 01 d0 88 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}