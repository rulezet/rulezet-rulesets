rule Trojan_Win32_Stealc_RPX_MTB_5{
	meta:
		description = "Trojan:Win32/Stealc.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 58 89 45 f0 81 45 f0 cb 07 00 00 8b 45 08 8b 4d f0 89 48 04 8b 45 f0 83 c0 3d 8b 4d 08 89 41 08 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}