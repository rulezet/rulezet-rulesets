rule Trojan_Win32_Stealc_RPX_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 04 3e 46 3b f3 7c f3 5e 83 fb 2d 75 14 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}